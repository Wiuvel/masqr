//! The HTTP/2 carrier: TCP, TLS, HTTP/2, one CONNECT, and packets as capsules on its stream.
//!
//! The shape is Cloudflare's, not RFC 9484's. A standards CONNECT-IP request uses extended CONNECT
//! with `:protocol = connect-ip`; this one is a plain HTTP/2 `CONNECT` to `cloudflareaccess.com`
//! with two headers naming the protocol, and the request body becomes the capsule stream. That
//! difference is why there is no crate to reach for: the framing is standard, the negotiation is
//! not.
//!
//! Once the response is 200, the two halves of the stream are the tunnel: capsules written into
//! the request body carry packets out, capsules read from the response body carry them back.

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::net::TcpStream;

use super::capsule;
use super::connect_ip::{
    ConnectError, Stages, Tunnel, TunnelHealth, TunnelReceiver, TunnelSender, decrement_hop_limit,
};
use crate::warp::Identity;

/// The authority the CONNECT request names. Not a host this core resolves or dials — the
/// connection is already open to the endpoint; this is the tunnel's own address inside it.
const CONNECT_AUTHORITY: &str = "cloudflareaccess.com:443";

/// The half that carries packets out.
pub struct Sender {
    outbound: h2::SendStream<Bytes>,
    /// Where a batch is assembled. Held rather than made per batch so the allocation is reused:
    /// `split` hands the filled part to the connection and leaves the rest here to be filled again.
    staging: BytesMut,
}

/// The half that carries packets back.
pub struct Receiver {
    inbound: h2::RecvStream,
    /// Bytes read from the stream that did not yet amount to a whole capsule.
    pending: BytesMut,
}

/// Whether the connection under the tunnel is still answering.
///
/// A link that goes away underneath a TCP connection leaves it neither closed nor working: packets
/// go out, nothing comes back, and nothing reports an error. HTTP/2 has exactly one way to ask.
pub struct Health {
    ping_pong: h2::PingPong,
}

impl Health {
    /// Ask the endpoint to answer, wait until it does, and say how long that took.
    ///
    /// One ping may be in flight at a time, so this is a single call that both asks and waits
    /// rather than two that could be interleaved. The time is a round trip on the tunnel itself,
    /// but one that waited behind everything already in the TCP send buffer: under load it measures
    /// the buffer as much as the link.
    pub async fn probe(&mut self) -> Result<Duration, ConnectError> {
        let asked = Instant::now();
        self.ping_pong.send_ping(h2::Ping::opaque())?;
        std::future::poll_fn(|cx| self.ping_pong.poll_pong(cx)).await?;
        Ok(asked.elapsed())
    }
}

/// Open the tunnel: TCP, TLS with the enrolled identity, HTTP/2, then CONNECT.
pub async fn connect(identity: &Identity) -> Result<(Tunnel, Stages), ConnectError> {
    let tls_config = super::tls::client_config(identity, b"h2")?;

    let endpoint: std::net::IpAddr = identity
        .endpoint_h2_v4
        .parse()
        .map_err(|_| ConnectError::BadEndpoint(identity.endpoint_h2_v4.clone()))?;
    let mark = Instant::now();
    let tcp = TcpStream::connect((endpoint, 443)).await?;
    let tcp_ms = mark.elapsed().as_millis();
    // The tunnel carries interactive traffic inside one stream, so Nagle would batch a packet
    // against the next one and add its delay to every small write.
    tcp.set_nodelay(true)?;

    let mark = Instant::now();
    // How the ClientHello goes out is the one thing about this connection that is under
    // experiment. See handshake.rs.
    let tls = super::handshake::connect_tls(tls_config, tcp, endpoint)
        .await
        .map_err(|e| {
            // A handshake that ends in end-of-file said nothing about why: no alert, no
            // ServerHello, just a closed connection. Measured on a filtered link, that is what a
            // blocked SNI looks like from here — the transport is fine, and the same endpoint
            // answers normally under a name nobody filters. Naming it beats reporting an
            // unexplained EOF, because the fix is not in this core.
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                let handshake = super::handshake::selected();
                ConnectError::HandshakeCut {
                    sni: handshake.sni().unwrap_or_else(|| "none".to_owned()),
                    how: handshake.name(),
                }
            } else {
                ConnectError::Io(e)
            }
        })?;
    let tls_ms = mark.elapsed().as_millis();

    let mark = Instant::now();
    // The windows are set rather than left at the default, because this connection is not a web
    // page: one stream carries every packet the machine sends. HTTP/2 starts at 64 KiB, and a
    // window that small means the endpoint must be asked for room again every 64 KiB — one round
    // trip per window, which on a link with any latency at all is the ceiling on throughput long
    // before the link is. Eight megabytes is enough that the room outlasts the round trip.
    let (mut send_request, mut connection) = h2::client::Builder::new()
        .initial_window_size(8 * 1024 * 1024)
        .initial_connection_window_size(16 * 1024 * 1024)
        .handshake(tls)
        .await?;
    let http2_ms = mark.elapsed().as_millis();
    // Taken before the connection is handed to its task, because that is the only moment it can be.
    let ping_pong = connection
        .ping_pong()
        .expect("nothing else has taken the ping handle of a connection made here");
    // The connection future drives the whole HTTP/2 session; nothing moves unless it is polled.
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::connect(CONNECT_AUTHORITY)
        // Named by Cloudflare rather than by the RFC: these two headers are what select CONNECT-IP
        // on a plain CONNECT.
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .header("user-agent", "")
        .body(())?;

    // `end_of_stream: false` is the point of the whole call: the request body stays open for as
    // long as the tunnel lives, because it IS the tunnel.
    let mark = Instant::now();
    let (response, outbound) = send_request.send_request(request, false)?;
    let response = response.await?;
    let connect_ms = mark.elapsed().as_millis();
    if !response.status().is_success() {
        return Err(ConnectError::Refused(response.status()));
    }

    Ok((
        Tunnel {
            sender: TunnelSender::H2(Sender {
                outbound,
                staging: BytesMut::new(),
            }),
            receiver: TunnelReceiver::H2(Receiver {
                inbound: response.into_body(),
                pending: BytesMut::new(),
            }),
            health: TunnelHealth::H2(Health { ping_pong }),
        },
        Stages::H2 {
            tcp_ms,
            tls_ms,
            http2_ms,
            connect_ms,
        },
    ))
}

impl Sender {
    /// Send a run of IP packets as one write, waiting for the room to do so.
    ///
    /// A run rather than a packet because the cost of a write does not scale with its size: each
    /// one is a frame header, a TLS record and a system call, and a busy tunnel pays all three
    /// thousands of times a second for packets that could have gone together. What they cannot do
    /// is go out of order, and they do not — the run is written in the order it is given.
    ///
    /// The wait is the other half. `send_data` on its own accepts whatever it is given and holds
    /// the excess in memory, so a sender faster than the flow-control window grows without bound
    /// instead of slowing down. Reserving first turns that into backpressure, which reaches back
    /// through the queue feeding this and becomes a decision about what to drop.
    pub async fn send(&mut self, packets: &mut [Vec<u8>]) -> Result<(), ConnectError> {
        for packet in packets.iter_mut() {
            // A packet whose hop limit is spent is left out rather than reported: that is what a
            // router does with one, and the sender learns from the absence of a reply.
            if decrement_hop_limit(packet) {
                capsule::encode_datagram_into(&mut self.staging, packet);
            }
        }
        if self.staging.is_empty() {
            return Ok(());
        }
        let frame = self.staging.split().freeze();

        self.outbound.reserve_capacity(frame.len());
        while self.outbound.capacity() < frame.len() {
            match std::future::poll_fn(|cx| self.outbound.poll_capacity(cx)).await {
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
                None => return Err(ConnectError::Closed),
            }
        }
        self.outbound.send_data(frame, false)?;
        Ok(())
    }
}

impl Receiver {
    /// Receive one IP packet, or `None` once the endpoint closed the tunnel.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, ConnectError> {
        loop {
            if let Some(capsule) = capsule::take_capsule(&mut self.pending)? {
                match capsule {
                    Some(payload) => return Ok(Some(payload.freeze())),
                    // A capsule of another type: consumed, and the loop looks for the next one.
                    None => continue,
                }
            }
            let Some(chunk) = self.inbound.data().await else {
                return Ok(None);
            };
            let chunk = chunk?;
            // Flow control is manual: the window only reopens once the data is accounted for, and
            // a tunnel that forgot this would stall after the first window.
            self.inbound.flow_control().release_capacity(chunk.len())?;
            self.pending.extend_from_slice(&chunk);
        }
    }
}
