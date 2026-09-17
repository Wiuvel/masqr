//! The HTTP/3 carrier: QUIC, HTTP/3, one extended CONNECT, and each packet a QUIC datagram.
//!
//! What the endpoint requires was measured against it, and agrees with the two working third-party
//! clients (usque and usque-rs):
//!
//! * The address is the one registration returns as the peer's endpoint, not the HTTP/2 one.
//! * Connection ids are 20 bytes. Shorter ones are refused now and then with PROTOCOL_VIOLATION.
//! * SETTINGS carry H3_DATAGRAM under both its RFC identifier and its draft-00 one.
//! * The request is extended CONNECT with `:protocol = cf-connect-ip` — Cloudflare's token; the
//!   RFC's `connect-ip` is refused with 403 — and `capsule-protocol: ?1`. The `cf-connect-proto`
//!   headers select CONNECT-IP over HTTP/2 and are not sent here.
//! * Nothing is written on the request stream after the request. A capsule written there got the
//!   stream reset.
//! * The name in the Initial is read on the way. WARP's own name and no name at all both get the
//!   handshake through and then the CONNECT left unanswered; `fronted` carries.
//!
//! Each packet is one datagram, `varint(stream id / 4) · 0 · packet`, so the path has to fit a
//! whole packet and that prefix into one. The handshake runs at QUIC's floor of 1200 bytes — the
//! size every client starts at, and the one measured to pass — and the tunnel is handed over once
//! path MTU discovery has made room for the adapter's largest packet. A path that never gets there
//! is not one this carrier can use, and HTTP/2 carries instead.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::VarInt;
use tokio::sync::{oneshot, watch};

use super::carrier;
use super::connect_ip::{
    ConnectError, LinkStats, Stages, Tunnel, TunnelHealth, TunnelReceiver, TunnelSender,
    decrement_hop_limit,
};
use super::http3::{
    self, ControlEvent, ControlStream, FrameReader, H3Error, PeerSettings, code, stream,
};
use crate::warp::Identity;

/// The request, as measured to open the tunnel. The authority is the tunnel's own name, not a host
/// this core dials.
const REQUEST: [(&[u8], &[u8]); 7] = [
    (b":method", b"CONNECT"),
    (b":protocol", b"cf-connect-ip"),
    (b":scheme", b"https"),
    (b":authority", b"cloudflareaccess.com"),
    (b":path", b"/"),
    (b"capsule-protocol", b"?1"),
    (b"user-agent", b""),
];

/// The connection id length the endpoint wants: the longest QUIC allows.
const CID_LEN: usize = 20;

/// How long the QUIC handshake may take. It is measured in tens of milliseconds; a link that drops
/// UDP to the endpoint never finishes it, and this is what that costs before HTTP/2 is tried.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(4);

/// How long SETTINGS and the CONNECT's answer may take, together, once the handshake is done.
/// Measured at 135–208 ms. A link that filters the name lets the handshake through and then
/// carries nothing, and this is how long it takes to say so.
const EXCHANGE_WAIT: Duration = Duration::from_secs(4);

/// How long path MTU discovery is given to make room for a full packet. Two probes reach it from
/// the starting size, one round trip each.
const PATH_WAIT: Duration = Duration::from_secs(2);
const PATH_POLL: Duration = Duration::from_millis(20);

/// A PING whenever the connection has been quiet this long.
///
/// This is what lets [`Health::probe`] ask its question passively: while the connection lives,
/// something arrives from the endpoint at least this often — the acknowledgement of a PING if
/// nothing else.
const KEEP_ALIVE: Duration = Duration::from_secs(2);

/// How long the connection survives hearing nothing at all. The engine's own check notices sooner;
/// this is what ends a connection nothing is asking about.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// The most outgoing datagram bytes QUIC holds before a send waits.
///
/// Small on purpose. A packet waiting here has left the queue in front of the tunnel, where the
/// flow queueing and CoDel decide what goes next and what is dropped; a packet waiting in QUIC's
/// buffer is in a plain FIFO that decides nothing. About two dozen full packets keeps the path fed
/// without moving the queue out of the place built to manage it.
const SEND_BUFFER: usize = 32 * 1024;

/// How often [`Health::probe`] looks for word from the endpoint.
const PROBE_POLL: Duration = Duration::from_millis(50);

/// How long a closed connection's endpoint is kept to send the close.
const LINGER: Duration = Duration::from_secs(1);

/// The connection and the socket it runs on, closed together.
///
/// Closed explicitly rather than by dropping the last handle: the tasks reading the endpoint's
/// streams hold handles too, so the connection would otherwise outlive the tunnel.
struct Link {
    connection: quinn::Connection,
    endpoint: quinn::Endpoint,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.connection.close(varint(code::NO_ERROR), b"");
        // The close is a packet the endpoint still has to send, and it goes with the endpoint. A
        // moment's grace lets the far side hear it rather than time the connection out.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let endpoint = self.endpoint.clone();
            runtime.spawn(async move {
                let _ = tokio::time::timeout(LINGER, endpoint.wait_idle()).await;
            });
        }
    }
}

/// What the three halves share.
struct Session {
    /// First, so it is dropped first: the connection is closed before the streams below are
    /// released, and they never get to finish.
    link: Link,
    /// This side's control stream and the request stream, never written again. Held because
    /// dropping either finishes it: the endpoint reads a finished control stream as a broken
    /// connection, and a finished request stream as the end of the tunnel.
    _control: quinn::SendStream,
    _request: quinn::SendStream,
}

/// Why the endpoint's side ended the tunnel, when it was not the connection failing.
#[derive(Debug, Clone)]
enum Ended {
    /// GOAWAY: the endpoint is shutting the connection down.
    GoingAway,
    /// The endpoint broke a rule; the connection was closed with the matching code.
    Broke(H3Error),
}

impl From<Ended> for ConnectError {
    fn from(ended: Ended) -> Self {
        match ended {
            Ended::GoingAway => ConnectError::GoingAway,
            Ended::Broke(error) => ConnectError::H3(error),
        }
    }
}

/// The reason for a lost connection: what the endpoint's streams recorded, when they recorded
/// anything, and QUIC's own account otherwise.
fn gone(ended: &watch::Receiver<Option<Ended>>, lost: quinn::ConnectionError) -> ConnectError {
    match ended.borrow().clone() {
        Some(ended) => ended.into(),
        None => ConnectError::Quic(lost),
    }
}

fn varint(code: u64) -> VarInt {
    VarInt::from_u64(code).expect("HTTP/3 error codes fit a varint")
}

/// The half that carries packets out.
pub struct Sender {
    session: Arc<Session>,
    stream_id: u64,
    ended: watch::Receiver<Option<Ended>>,
}

/// The half that carries packets back.
pub struct Receiver {
    session: Arc<Session>,
    /// The response side of the request stream. Nothing is expected on it after the response;
    /// it is read so that its end is seen, because its end is the tunnel's.
    response: quinn::RecvStream,
    stream_id: u64,
    ended: watch::Receiver<Option<Ended>>,
}

/// Whether the endpoint is still answering.
pub struct Health {
    session: Arc<Session>,
    ended: watch::Receiver<Option<Ended>>,
}

impl Sender {
    /// Send a run of IP packets, one datagram each, waiting for room in QUIC's buffer.
    ///
    /// The wait is the backpressure: a send that cannot get into the buffer holds the queue in
    /// front of the tunnel, which is where the decision about what to drop belongs.
    pub async fn send(&mut self, packets: &mut [Vec<u8>]) -> Result<(), ConnectError> {
        let connection = &self.session.link.connection;
        for packet in packets.iter_mut() {
            // A packet whose hop limit is spent is left out rather than reported: that is what a
            // router does with one.
            if !decrement_hop_limit(packet) {
                continue;
            }
            let datagram = http3::datagram(self.stream_id, packet);
            match connection.send_datagram_wait(datagram).await {
                Ok(()) => {}
                // The room was there when the tunnel opened and is gone: the path's MTU fell.
                // Every full-size packet from here on would be lost, which the connections inside
                // would read as a black hole, so the tunnel ends instead and a fresh one decides
                // again whether this path can carry it.
                Err(quinn::SendDatagramError::TooLarge) => {
                    return Err(ConnectError::H3Unfit(format!(
                        "a {}-byte packet no longer fits the path, which now takes {} bytes",
                        packet.len(),
                        connection.max_datagram_size().unwrap_or(0)
                    )));
                }
                Err(
                    quinn::SendDatagramError::UnsupportedByPeer
                    | quinn::SendDatagramError::Disabled,
                ) => {
                    return Err(ConnectError::H3Unfit(
                        "the endpoint stopped taking datagrams".into(),
                    ));
                }
                Err(quinn::SendDatagramError::ConnectionLost(lost)) => {
                    return Err(gone(&self.ended, lost));
                }
            }
        }
        Ok(())
    }
}

impl Receiver {
    /// Receive one IP packet, or `None` once the endpoint ended the tunnel.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, ConnectError> {
        loop {
            tokio::select! {
                biased;
                datagram = self.session.link.connection.read_datagram() => match datagram {
                    Ok(datagram) => {
                        // Another request's datagram, or another context, is dropped (RFC 9484
                        // §6) and the wait goes on.
                        if let Some(packet) = http3::datagram_packet(datagram, self.stream_id) {
                            return Ok(Some(packet));
                        }
                    }
                    Err(lost) => return Err(gone(&self.ended, lost)),
                },
                chunk = self.response.read_chunk(usize::MAX, true) => match chunk {
                    // A capsule the endpoint chose to send: nothing this tunnel acts on.
                    Ok(Some(_)) => {}
                    Ok(None) => return Ok(None),
                    Err(problem) => return Err(problem.into()),
                },
                Ok(()) = self.ended.changed() => {
                    if let Some(ended) = self.ended.borrow_and_update().clone() {
                        return Err(ended.into());
                    }
                }
            }
        }
    }
}

impl Health {
    /// What QUIC knows about this connection's path, for a journal line that has to say whether a
    /// loss was the line's or this side's.
    pub fn link_stats(&self) -> LinkStats {
        let stats = self.session.link.connection.stats();
        LinkStats {
            rtt: stats.path.rtt,
            cwnd: stats.path.cwnd,
            sent: stats.path.sent_packets,
            lost: stats.path.lost_packets,
            datagrams_in: stats.frame_rx.datagram,
        }
    }

    /// Wait for word from the endpoint, and give QUIC's round-trip estimate when it comes.
    ///
    /// HTTP/2's ping has no counterpart to call here, and it is not needed: with [`KEEP_ALIVE`]
    /// running, a live connection hears from the endpoint within a couple of seconds whatever the
    /// traffic, and a dead one does not. The round trip is QUIC's own, taken from acknowledgements
    /// — the time a packet spends on the path, with none of this side's queueing in it.
    pub async fn probe(&mut self) -> Result<Duration, ConnectError> {
        let connection = &self.session.link.connection;
        let heard = connection.stats().udp_rx.datagrams;
        loop {
            if let Some(lost) = connection.close_reason() {
                return Err(gone(&self.ended, lost));
            }
            if connection.stats().udp_rx.datagrams > heard {
                return Ok(connection.rtt());
            }
            tokio::time::sleep(PROBE_POLL).await;
        }
    }
}

/// What the tasks reading the endpoint's streams share with the connection.
struct Peer {
    connection: quinn::Connection,
    control_seen: AtomicBool,
    settings: Mutex<Option<oneshot::Sender<PeerSettings>>>,
    ended: watch::Sender<Option<Ended>>,
}

impl Peer {
    /// Record why, and close the connection with the code that says it.
    fn fail(&self, error: H3Error) {
        let code = error.code();
        let reason = error.to_string();
        self.ended.send_replace(Some(Ended::Broke(error)));
        self.connection.close(varint(code), reason.as_bytes());
    }
}

/// Accept the streams the endpoint opens, for the life of the connection.
async fn accept_streams(peer: Arc<Peer>) {
    while let Ok(incoming) = peer.connection.accept_uni().await {
        tokio::spawn(serve_stream(Arc::clone(&peer), incoming));
    }
}

/// One of the endpoint's unidirectional streams, read according to the type it opens with.
async fn serve_stream(peer: Arc<Peer>, mut incoming: quinn::RecvStream) {
    let mut reader = FrameReader::new();
    let kind = loop {
        if let Some(kind) = reader.take_varint() {
            break kind;
        }
        match incoming.read_chunk(usize::MAX, true).await {
            Ok(Some(chunk)) => reader.extend(&chunk.bytes),
            _ => return,
        }
    };
    match kind {
        stream::CONTROL => {
            if peer.control_seen.swap(true, Ordering::Relaxed) {
                peer.fail(H3Error::SecondControl);
            } else if let Err(error) = serve_control(&peer, incoming, reader).await {
                peer.fail(error);
            }
        }
        // With no dynamic table on either side there is nothing on these to act on. They are read
        // to the end so the endpoint never waits on flow control for them.
        stream::QPACK_ENCODER | stream::QPACK_DECODER => {
            while let Ok(Some(_)) = incoming.read_chunk(usize::MAX, true).await {}
        }
        // Push was never enabled, and anything else is a type this side does not know: RFC 9114
        // §6.2 lets a receiver refuse either.
        _ => {
            let _ = incoming.stop(varint(code::STREAM_CREATION_ERROR));
        }
    }
}

/// The endpoint's control stream: its SETTINGS go to the connection being opened, a GOAWAY ends the
/// tunnel, and the stream ending while the connection lives is an error.
async fn serve_control(
    peer: &Peer,
    mut incoming: quinn::RecvStream,
    mut reader: FrameReader,
) -> Result<(), H3Error> {
    let mut control = ControlStream::default();
    loop {
        while let Some(frame) = reader.next_frame()? {
            match control.on_frame(frame)? {
                Some(ControlEvent::Settings(settings)) => {
                    let waiting = peer
                        .settings
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take();
                    if let Some(waiting) = waiting {
                        let _ = waiting.send(settings);
                    }
                }
                Some(ControlEvent::GoAway(_)) => {
                    // Kept to the first reason: a rule broken earlier says more than the goodbye.
                    peer.ended.send_if_modified(|ended| {
                        let first = ended.is_none();
                        if first {
                            *ended = Some(Ended::GoingAway);
                        }
                        first
                    });
                }
                None => {}
            }
        }
        match incoming.read_chunk(usize::MAX, true).await {
            Ok(Some(chunk)) => reader.extend(&chunk.bytes),
            Ok(None) | Err(quinn::ReadError::Reset(_)) => return Err(H3Error::ControlClosed),
            // The connection went. That is reported where it is felt, by the tunnel's halves.
            Err(_) => return Ok(()),
        }
    }
}

/// Read the request stream up to the final response.
async fn read_response(response: &mut quinn::RecvStream) -> Result<http::StatusCode, ConnectError> {
    let mut reader = FrameReader::new();
    loop {
        while let Some(frame) = reader.next_frame()? {
            if let Some(status) = http3::response_status(frame)? {
                return Ok(status);
            }
        }
        match response.read_chunk(usize::MAX, true).await? {
            Some(chunk) => reader.extend(&chunk.bytes),
            None => return Err(H3Error::Message("ended before it began").into()),
        }
    }
}

/// Wait until the path fits a datagram of `needed` bytes.
async fn wait_for_room(connection: &quinn::Connection, needed: usize) -> Result<(), ConnectError> {
    let deadline = Instant::now() + PATH_WAIT;
    loop {
        let room = connection
            .max_datagram_size()
            .ok_or_else(|| ConnectError::H3Unfit("the endpoint takes no datagrams".into()))?;
        if room >= needed {
            return Ok(());
        }
        if let Some(lost) = connection.close_reason() {
            return Err(ConnectError::Quic(lost));
        }
        if Instant::now() >= deadline {
            return Err(ConnectError::H3Unfit(format!(
                "the path takes {room}-byte datagrams, and a full packet needs {needed}"
            )));
        }
        tokio::time::sleep(PATH_POLL).await;
    }
}

fn transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            IDLE_TIMEOUT
                .try_into()
                .expect("ten seconds is a valid idle timeout"),
        ))
        .keep_alive_interval(Some(KEEP_ALIVE))
        .datagram_send_buffer_size(SEND_BUFFER)
        // An HTTP/3 server never opens a bidirectional stream to a client.
        .max_concurrent_bidi_streams(VarInt::from_u32(0));
    transport
}

/// Open the tunnel: QUIC with the enrolled identity, SETTINGS both ways, then CONNECT.
pub async fn connect(identity: &Identity) -> Result<(Tunnel, Stages), ConnectError> {
    let written = identity.endpoint_h3_v4();
    let address: IpAddr = written
        .parse()
        .map_err(|_| ConnectError::BadEndpoint(written.to_string()))?;
    connect_at(identity, SocketAddr::new(address, 443)).await
}

/// The same, to a given address and port.
async fn connect_at(
    identity: &Identity,
    peer: SocketAddr,
) -> Result<(Tunnel, Stages), ConnectError> {
    let address = peer.ip();
    let tls = super::tls::client_config(identity, b"h3")?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|problem| {
        ConnectError::QuicUnavailable(format!("the TLS setup cannot run inside QUIC: {problem}"))
    })?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport_config()));

    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let mut config = quinn::EndpointConfig::default();
    config.cid_generator(|| Box::new(quinn_proto::RandomConnectionIdGenerator::new(CID_LEN)));
    let endpoint = quinn::Endpoint::new(config, None, socket, Arc::new(quinn::TokioRuntime))?;

    let handshake = super::handshake::selected();
    let literal = address.to_string();
    let sni_opt = handshake.sni();
    let name = sni_opt.as_deref().unwrap_or(&literal);

    let mark = Instant::now();
    let connecting = endpoint
        .connect_with(client, peer, name)
        .map_err(|problem| ConnectError::QuicUnavailable(problem.to_string()))?;
    let connection = match tokio::time::timeout(HANDSHAKE_WAIT, connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(problem)) => return Err(ConnectError::QuicUnavailable(problem.to_string())),
        Err(_) => {
            return Err(ConnectError::QuicUnavailable(format!(
                "no answer within {} s",
                HANDSHAKE_WAIT.as_secs()
            )));
        }
    };
    let quic_ms = mark.elapsed().as_millis();
    // From here every way out closes the connection, the successful one included once the tunnel
    // is dropped.
    let link = Link {
        connection: connection.clone(),
        endpoint,
    };

    let (settings_sent, settings) = oneshot::channel();
    let (ended_sender, ended) = watch::channel(None);
    tokio::spawn(accept_streams(Arc::new(Peer {
        connection: connection.clone(),
        control_seen: AtomicBool::new(false),
        settings: Mutex::new(Some(settings_sent)),
        ended: ended_sender,
    })));

    // SETTINGS both ways, then the request. The endpoint's SETTINGS are waited for before the
    // request goes: extended CONNECT and datagrams may only be used once the endpoint has said it
    // takes them (RFC 9220 §3, RFC 9297 §2.1.1).
    let exchange = async {
        let mark = Instant::now();
        let mut control = connection.open_uni().await?;
        control.write_all(&http3::control_stream_preface()).await?;
        let offered = settings.await.map_err(|_| {
            connection
                .close_reason()
                .map_or(ConnectError::H3(H3Error::ControlClosed), ConnectError::Quic)
        })?;
        let settings_ms = mark.elapsed().as_millis();
        if !offered.h3_datagram {
            return Err(ConnectError::H3Unfit(
                "the endpoint does not offer HTTP datagrams".into(),
            ));
        }
        if !offered.extended_connect {
            return Err(ConnectError::H3Unfit(
                "the endpoint does not offer extended CONNECT".into(),
            ));
        }

        let mark = Instant::now();
        let (mut request, mut response) = connection.open_bi().await?;
        request.write_all(&http3::headers_frame(&REQUEST)).await?;
        let status = read_response(&mut response).await?;
        Ok((control, request, response, status, settings_ms, mark))
    };
    let (control, request, response, status, settings_ms, mark) =
        match tokio::time::timeout(EXCHANGE_WAIT, exchange).await {
            Ok(Ok(exchanged)) => exchanged,
            Ok(Err(problem)) => {
                if let ConnectError::H3(broken) = &problem {
                    connection.close(varint(broken.code()), broken.to_string().as_bytes());
                }
                // What the endpoint's streams recorded explains a failure better than the
                // connection error it caused.
                return Err(ended.borrow().clone().map_or(problem, ConnectError::from));
            }
            Err(_) => {
                return Err(ConnectError::H3Unanswered {
                    sni: handshake.sni().unwrap_or_else(|| "none".to_owned()),
                    how: handshake.name(),
                });
            }
        };
    if !status.is_success() {
        return Err(ConnectError::H3Refused(status));
    }

    let stream_id = u64::from(request.id());
    wait_for_room(
        &connection,
        carrier::largest_packet() + http3::datagram_overhead(stream_id),
    )
    .await?;
    let connect_ms = mark.elapsed().as_millis();

    let session = Arc::new(Session {
        link,
        _control: control,
        _request: request,
    });
    Ok((
        Tunnel {
            sender: TunnelSender::H3(Sender {
                session: Arc::clone(&session),
                stream_id,
                ended: ended.clone(),
            }),
            receiver: TunnelReceiver::H3(Receiver {
                session: Arc::clone(&session),
                response,
                stream_id,
                ended: ended.clone(),
            }),
            health: TunnelHealth::H3(Health { session, ended }),
        },
        Stages::H3 {
            quic_ms,
            settings_ms,
            connect_ms,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::carrier::Carrier;
    use crate::transport::qpack;

    /// How the stand-in endpoint answers the CONNECT.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Answer {
        Open,
        Refuse,
        /// Open, echo one datagram, then send GOAWAY on its control stream.
        OpenThenGoAway,
    }

    type Read = oneshot::Receiver<(PeerSettings, Vec<qpack::Field>)>;

    /// An HTTP/3 endpoint on loopback, written with this core's own framing: SETTINGS on a control
    /// stream, one CONNECT answered, and every datagram sent straight back. It judges nothing
    /// itself; what it read is handed to the test to assert on.
    ///
    /// Its certificate carries a key of its own, and the identity handed back pins that key, so the
    /// client's verifier runs exactly as it does against the real endpoint.
    async fn stand_in(answer: Answer) -> (SocketAddr, Identity, Read) {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
        let certificate = rcgen::CertificateParams::new(vec!["masque.cloudflareclient.com".into()])
            .expect("a name")
            .self_signed(&key)
            .expect("a certificate");
        let private =
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).expect("a PKCS#8 key");
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private)
            .expect("a server config");
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC-able");
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )
        .expect("a loopback endpoint");
        let address = server.local_addr().expect("the port it took");

        let keys = crate::warp::keys::MasqueKeyPair::generate().expect("a client key");
        let identity = Identity {
            device_id: "stand-in".into(),
            access_token: String::new(),
            license: String::new(),
            private_key_sec1: keys.private_sec1_base64,
            endpoint_public_key_pem: key.public_key_pem(),
            assigned_v4: "172.16.0.2".into(),
            assigned_v6: "2606:4700::1".into(),
            endpoint_h2_v4: "127.0.0.1".into(),
            endpoint_v4: "127.0.0.1".into(),
            endpoint_v6: String::new(),
        };

        let (read, what_was_read) = oneshot::channel();
        tokio::spawn(async move {
            let connection = server
                .accept()
                .await
                .expect("a client")
                .await
                .expect("a handshake");
            let mut control = connection.open_uni().await.expect("a control stream");
            control
                .write_all(&http3::control_stream_preface())
                .await
                .expect("SETTINGS out");

            let mut theirs = connection.accept_uni().await.expect("their control stream");
            let mut reader = FrameReader::new();
            let mut typed = false;
            let settings = loop {
                if !typed {
                    typed = reader.take_varint() == Some(stream::CONTROL);
                }
                if typed && let Some(frame) = reader.next_frame().expect("well-formed frames") {
                    break PeerSettings::parse(&frame.payload).expect("their SETTINGS");
                }
                let chunk = theirs.read_chunk(usize::MAX, true).await.unwrap().unwrap();
                reader.extend(&chunk.bytes);
            };

            let (mut respond, mut request) = connection.accept_bi().await.expect("the CONNECT");
            let mut reader = FrameReader::new();
            let fields = loop {
                if let Some(frame) = reader.next_frame().expect("well-formed frames") {
                    break qpack::decode(&frame.payload).expect("a readable header block");
                }
                let chunk = request.read_chunk(usize::MAX, true).await.unwrap().unwrap();
                reader.extend(&chunk.bytes);
            };
            let _ = read.send((settings, fields));

            let status: &[u8] = if answer == Answer::Refuse {
                b"403"
            } else {
                b"200"
            };
            respond
                .write_all(&http3::headers_frame(&[(b":status", status)]))
                .await
                .expect("the response");

            while let Ok(datagram) = connection.read_datagram().await {
                let _ = connection.send_datagram(datagram);
                if answer == Answer::OpenThenGoAway {
                    // GOAWAY naming stream 4: the CONNECT on stream 0 is still served.
                    let _ = control.write_all(&[0x07, 0x01, 0x04]).await;
                }
            }
            // Held to here, so neither stream is finished while the client is using the tunnel.
            drop((control, respond));
        });
        (address, identity, what_was_read)
    }

    /// An IPv4 packet with a real header, so the hop count can be decremented on the way out.
    fn packet() -> Vec<u8> {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 172, 16, 0, 2,
            1, 1, 1, 1,
        ];
        let checksum = crate::ip::ipv4_checksum(&packet);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(b"twelve bytes");
        packet
    }

    /// The whole carrier against an endpoint that behaves: the pin verifies, SETTINGS cross, the
    /// request arrives as it was measured to open the real tunnel, path MTU discovery makes room for
    /// a full packet, and a packet goes out and comes back.
    #[tokio::test]
    async fn a_tunnel_opens_and_carries_a_packet_both_ways() {
        let (address, identity, read) = stand_in(Answer::Open).await;
        let (mut tunnel, stages) = connect_at(&identity, address)
            .await
            .expect("the stand-in opens the tunnel");
        assert_eq!(stages.carrier(), Carrier::H3);

        let (settings, fields) = read.await.expect("the stand-in read the request");
        assert!(settings.h3_datagram && settings.extended_connect);
        let asked: Vec<qpack::Field> = REQUEST
            .iter()
            .map(|&(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(fields, asked);

        let sent = packet();
        tunnel.send(sent.clone()).await.expect("sent");
        let back = tokio::time::timeout(Duration::from_secs(2), tunnel.recv())
            .await
            .expect("an echo within two seconds")
            .expect("no error")
            .expect("a packet");
        assert_eq!(
            back[8],
            sent[8] - 1,
            "the hop count was spent once, on the way out"
        );
        assert_eq!(&back[20..], &sent[20..]);

        let round_trip = tokio::time::timeout(Duration::from_secs(5), tunnel.health.probe())
            .await
            .expect("the keep-alive brings word within five seconds")
            .expect("the endpoint answers");
        assert!(round_trip < Duration::from_secs(1));
    }

    /// A refusal over HTTP/3 is its own error, so the engine never reads it as the device being
    /// declined.
    #[tokio::test]
    async fn a_refusal_is_reported_as_an_http3_refusal() {
        let (address, identity, _read) = stand_in(Answer::Refuse).await;
        let refused = connect_at(&identity, address)
            .await
            .err()
            .expect("the stand-in refuses");
        assert!(
            matches!(&refused, ConnectError::H3Refused(status) if *status == http::StatusCode::FORBIDDEN),
            "{refused}"
        );
    }

    /// GOAWAY ends the tunnel with its own reason, so the engine opens a fresh one.
    #[tokio::test]
    async fn goaway_ends_the_tunnel() {
        let (address, identity, _read) = stand_in(Answer::OpenThenGoAway).await;
        let (mut tunnel, _) = connect_at(&identity, address)
            .await
            .expect("the stand-in opens the tunnel");
        tunnel.send(packet()).await.expect("sent");

        let ended = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match tunnel.recv().await {
                    Ok(Some(_)) => continue,
                    Ok(None) => panic!("the tunnel ended without a reason"),
                    Err(problem) => return problem,
                }
            }
        })
        .await
        .expect("GOAWAY within two seconds");
        assert!(matches!(ended, ConnectError::GoingAway), "{ended}");
    }
}
