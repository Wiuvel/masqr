//! How the tunnel's own ClientHello is put on the wire. Experimental.
//!
//! Measured on a filtered link: TCP to the endpoint establishes, the TLS handshake carrying the SNI
//! `consumer-masque.cloudflareclient.com` is closed with no byte of reply, and the same address
//! under an unfiltered name answers in full. The name in the clear is what is matched — not the
//! address, not the fingerprint.
//!
//! That is why the shipped path needs a DPI bypass running underneath the tunnel, and why the
//! application pins the endpoint's addresses and `*.cloudflareclient.com` undeletable in the bypass
//! lists. This module asks whether the core can get its own handshake through instead.
//!
//! **Two levers, and only two.** A bypass engine rewrites packets on the wire — short-TTL fakes,
//! overlapping splits, deliberately wrong checksums — and all of that needs a raw socket. This core
//! has an ordinary TCP connection, so what it can vary is which name it sends and where the bytes
//! fall across segment boundaries. Every strategy here is one of the two.
//!
//! Over QUIC only the first lever exists. The ClientHello travels inside the QUIC Initial, which a
//! DPI can decrypt — its keys come from the packet itself — and there is no stream to cut. The name
//! strategies apply to both carriers through [`Handshake::server_name`]; the split ones are
//! HTTP/2's alone.
//!
//! The choice is process-wide and set once, like the log level: it belongs to a run, not to a
//! connection, and threading it through would put an experiment's parameter in the signature of the
//! path that carries every packet.
//!
//! A run starts at [`Handshake::Named`]. The endpoint completes CONNECT-IP with no name at all and
//! the pinned key still verifies, so it does not route by the name — but opening a tunnel and
//! keeping one are different properties, and in the field the nameless session came up and then
//! lost its HTTP/2 ping every few seconds. [`Handshake::NoSni`] stays a flag until a run shows it
//! carrying. `masqr handshake` holds each tunnel open and pings it for that reason.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::warp::CONNECT_SNI;

/// An unfiltered Cloudflare name, presented in place of the one the tunnel is really for.
///
/// It began as a control — a way to tell "this link blocks the name" from "this link blocks the
/// endpoint". It turned out to be the only thing that carries: measured on the line, with no bypass
/// under it, a tunnel opened under this name moved 76.8 KiB both ways and stayed up, while every
/// other strategy died at 19.2 KiB. The endpoint does not read SNI, so the name costs nothing on
/// the far side and buys the flow a classification that is not acted on.
const FRONTED_SNI: &str = "www.cloudflare.com";

/// The name `fronted` presents in place of [`FRONTED_SNI`], when a run was given one.
///
/// Set via the command line or changed at runtime via the control pipe. It exists to measure
/// which other names a link does not act on, and to fall back to them when the link starts acting
/// on the default one.
static FRONTED_NAME: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Change the name the `fronted` strategy uses.
///
/// Refused when it is not a DNS name — an address in SNI is forbidden, and `no-sni` is the strategy
/// for sending none.
pub fn set_fronted_name(name: &str) -> Result<(), String> {
    match rustls::pki_types::ServerName::try_from(name) {
        Ok(rustls::pki_types::ServerName::DnsName(_)) => {}
        _ => return Err(format!("`{name}` is not a DNS name")),
    }
    FRONTED_NAME.write().unwrap().replace(name.to_owned());
    Ok(())
}

/// The name the `fronted` strategy uses.
pub fn fronted_name() -> String {
    FRONTED_NAME
        .read()
        .unwrap()
        .as_ref()
        .cloned()
        .unwrap_or_else(|| FRONTED_SNI.to_owned())
}

/// How long the second half of a split ClientHello is held back.
///
/// A DPI that reassembles a stream usually does so within a window. Waiting past it means the
/// first segment has already been judged — on its own, without the whole name in it — by the time
/// the rest arrives. Long enough to outlast a short window, short enough to be invisible against a
/// handshake that already costs a round trip.
const SPLIT_DELAY: Duration = Duration::from_millis(40);

/// How the ClientHello for the tunnel's TLS session is presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handshake {
    /// The name Cloudflare's own client sends, in one write.
    ///
    /// What the core did until 2026-09-04, and what to reach for if the endpoint ever starts
    /// requiring its own name. On a link that filters that name it is the one strategy that cannot
    /// get through: the flow is classified by it and cut at 19.2 KiB.
    Named,
    /// No `server_name` extension at all.
    ///
    /// Sending a literal address as SNI is forbidden (RFC 6066), so rustls omits the extension
    /// entirely when the server name is an address — which is the whole trick: there is no name in
    /// the clear to match. The endpoint accepts it and the pinned key verifies, so it does not
    /// route by the name.
    ///
    /// **It is not the default, and the reason is measured.** A session opened this way came up and
    /// then stopped answering its ping within seconds, repeatedly. Whether that is the edge putting
    /// a nameless connection somewhere less durable is not established — what is established is
    /// that opening is not carrying, and this one was only ever shown to open.
    NoSni,
    /// The expected name, cut across a TCP segment boundary inside the name itself.
    ///
    /// Defeats a DPI that judges each segment on its own. One that reassembles the stream sees the
    /// name regardless, so this is a measurement, not a remedy.
    Split,
    /// The same cut, with the remainder held back past a reassembly window.
    SplitSlow,
    /// An unfiltered Cloudflare name in place of the tunnel's own, in one write.
    ///
    /// **This carries where the others do not**, and the measurement is not subtle: on the line,
    /// unaided, it moved 76.8 KiB in both directions and held its pings, while `named`, `no-sni`
    /// and both splits each died at exactly 19.2 KiB. Same address, same path, same minute — only
    /// the name differs. So the flow is classified by the name and then cut on volume, and a name
    /// that is not acted on is not cut.
    ///
    /// It is a real tunnel, not a probe: the endpoint presents the key registration enrolled and
    /// the pin verifies. It is also still the control the verdict reads — a link that lets this
    /// through and nothing else is a link filtering the name rather than the address.
    ///
    /// **The default since 2026-09-04.** Two field runs with no bypass under them carried 223.7 MiB
    /// with no tunnel lost. On a link that does not filter the name it costs nothing, because the
    /// endpoint does not read SNI at all; on one that does, it is the difference between a tunnel
    /// and 19.2 KiB.
    Fronted,
}

impl Handshake {
    /// Every strategy, in the order a diagnostic run should try them: the control first, then
    /// cheapest to most disruptive.
    pub const ALL: [Handshake; 5] = [
        Handshake::Named,
        Handshake::NoSni,
        Handshake::Split,
        Handshake::SplitSlow,
        Handshake::Fronted,
    ];

    /// The name this is written as on the command line.
    pub fn name(self) -> &'static str {
        match self {
            Handshake::Named => "named",
            Handshake::NoSni => "no-sni",
            Handshake::Split => "split",
            Handshake::SplitSlow => "split-slow",
            Handshake::Fronted => "fronted",
        }
    }

    /// One line on what it does, for the diagnostic's own output.
    pub fn describes(self) -> &'static str {
        match self {
            Handshake::Named => "the expected name, in one write",
            Handshake::NoSni => "no name at all",
            Handshake::Split => "the name, cut across two segments",
            Handshake::SplitSlow => "the same cut, second half held back",
            Handshake::Fronted => "an unfiltered Cloudflare name instead",
        }
    }

    pub fn parse(written: &str) -> Option<Handshake> {
        Handshake::ALL.into_iter().find(|h| h.name() == written)
    }

    /// Whether this strategy means anything over QUIC. The splits cut TCP segments, and a QUIC
    /// connection has none.
    pub fn works_over_quic(self) -> bool {
        !matches!(self, Handshake::Split | Handshake::SplitSlow)
    }

    /// The name the ClientHello carries, over either carrier, or `None` for no name at all.
    ///
    /// No name is sent by giving rustls the endpoint's address instead: RFC 6066 forbids a literal
    /// in SNI, so the extension is left out. The verifier pins the endpoint's public key and never
    /// reads the name, so an address costs nothing — it is not a claim about who the peer is, only
    /// the absence of one.
    pub fn sni(self) -> Option<String> {
        match self {
            Handshake::NoSni => None,
            // The unwrap is safe: what was set has already passed `DnsName` validation.
            Handshake::Fronted => Some(fronted_name()),
            _ => Some(CONNECT_SNI.to_owned()),
        }
    }

    const fn code(self) -> u8 {
        match self {
            Handshake::Named => 0,
            Handshake::NoSni => 1,
            Handshake::Split => 2,
            Handshake::SplitSlow => 3,
            Handshake::Fronted => 4,
        }
    }

    fn from_code(code: u8) -> Handshake {
        match code {
            1 => Handshake::NoSni,
            2 => Handshake::Split,
            3 => Handshake::SplitSlow,
            4 => Handshake::Fronted,
            // Including the value the atomic starts at: a run that chose nothing sends the name.
            _ => Handshake::Named,
        }
    }
}

/// What a run uses unless the command line says otherwise. See [`Handshake::Fronted`].
const DEFAULT: Handshake = Handshake::Fronted;

/// The strategy in force, held as its `code()` so it fits an atomic.
static SELECTED: AtomicU8 = AtomicU8::new(DEFAULT.code());

/// Choose the strategy every later connection uses.
pub fn select(handshake: Handshake) {
    SELECTED.store(handshake.code(), Ordering::Relaxed);
}

/// The strategy in force.
pub fn selected() -> Handshake {
    Handshake::from_code(SELECTED.load(Ordering::Relaxed))
}

/// Open the TLS session over an established connection, presenting the ClientHello the selected
/// strategy calls for.
///
/// The stream type does not depend on the strategy: the socket is always wrapped, and a wrapper
/// with nothing to do passes every byte straight through.
pub async fn connect_tls(
    config: Arc<rustls::ClientConfig>,
    tcp: TcpStream,
    endpoint: std::net::IpAddr,
) -> io::Result<TlsStream<HandshakeStream>> {
    let handshake = selected();
    let server_name = match handshake.sni() {
        Some(name) => name_of(&name)?,
        None => rustls::pki_types::ServerName::IpAddress(endpoint.into()),
    };

    TlsConnector::from(config)
        .connect(server_name, HandshakeStream::wrapping(tcp, handshake))
        .await
}

fn name_of(name: &str) -> io::Result<rustls::pki_types::ServerName<'static>> {
    rustls::pki_types::ServerName::try_from(name.to_owned()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{name}` is not a name"),
        )
    })
}

/// The socket the handshake is written to.
///
/// Present whichever strategy is running, so that nothing downstream of the handshake has a type
/// that varies with an experiment. With no plan it forwards every call unchanged.
pub struct HandshakeStream<S = TcpStream> {
    inner: S,
    plan: Option<SplitPlan>,
}

impl<S> HandshakeStream<S> {
    /// Wrap a socket with the plan the given strategy calls for.
    fn wrapping(inner: S, handshake: Handshake) -> Self {
        let plan = match handshake {
            Handshake::Split => Some(SplitPlan::new(CONNECT_SNI.as_bytes(), None)),
            Handshake::SplitSlow => Some(SplitPlan::new(CONNECT_SNI.as_bytes(), Some(SPLIT_DELAY))),
            _ => None,
        };
        Self { inner, plan }
    }
}

/// Where to cut the first write, and how long to wait before the rest of it.
struct SplitPlan {
    /// The name to cut inside. Cutting at an arbitrary offset can leave the whole name in the
    /// first segment, which is the one thing this must not do.
    needle: &'static [u8],
    delay: Option<Duration>,
    state: SplitState,
}

enum SplitState {
    /// Nothing written yet.
    Waiting,
    /// The first segment is out; the rest is held until this elapses.
    Holding(Pin<Box<tokio::time::Sleep>>),
    /// Done — every later write is ordinary.
    Through,
}

impl SplitPlan {
    fn new(needle: &'static [u8], delay: Option<Duration>) -> Self {
        Self {
            needle,
            delay,
            state: SplitState::Waiting,
        }
    }
}

/// Where to stop the first write so the name straddles the boundary.
///
/// The middle of the name when it is there to find, and the middle of the buffer when it is not —
/// a ClientHello without the name in the clear is one there is nothing to hide in, and half a
/// buffer is still a cut.
fn cut_point(buffer: &[u8], needle: &[u8]) -> Option<usize> {
    let at = buffer
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|start| start + needle.len() / 2)
        .unwrap_or(buffer.len() / 2);
    (at > 0 && at < buffer.len()).then_some(at)
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HandshakeStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let Some(plan) = this.plan.as_mut() else {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        };

        match &mut plan.state {
            SplitState::Waiting => {
                let Some(at) = cut_point(buf, plan.needle) else {
                    plan.state = SplitState::Through;
                    return Pin::new(&mut this.inner).poll_write(cx, buf);
                };
                // A short write, not two writes: the caller is told how much went, and comes back
                // with the rest. Two segments on the wire, and no buffer of our own to own.
                let written =
                    std::task::ready!(Pin::new(&mut this.inner).poll_write(cx, &buf[..at]))?;
                plan.state = match plan.delay {
                    Some(delay) => SplitState::Holding(Box::pin(tokio::time::sleep(delay))),
                    None => SplitState::Through,
                };
                Poll::Ready(Ok(written))
            }
            SplitState::Holding(sleep) => {
                std::task::ready!(sleep.as_mut().poll(cx));
                plan.state = SplitState::Through;
                Pin::new(&mut this.inner).poll_write(cx, buf)
            }
            SplitState::Through => Pin::new(&mut this.inner).poll_write(cx, buf),
        }
    }

    /// Vectored writes, forwarded once there is nothing left to split.
    ///
    /// This matters far more than the split does. The wrapper exists for one ClientHello, but it
    /// stays under the connection for its whole life, and **every packet the tunnel carries is
    /// written through it**. Leaving the default implementation in place meant the TLS layer's
    /// record header, payload and tag stopped going out in one call and became a syscall each —
    /// paid per packet, forever, so that one handshake could be cut in half.
    ///
    /// While a plan is pending the fallback is deliberate: the split has to see the bytes, so the
    /// first buffer is handed to `poll_write` and the caller comes back for the rest.
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.is_write_vectored() {
            return Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        }
        let first = bufs.iter().find(|b| !b.is_empty()).map_or(&[][..], |b| b);
        self.poll_write(cx, first)
    }

    fn is_write_vectored(&self) -> bool {
        // A plan that has already run through leaves nothing to intercept, so the wrapper gets out
        // of the way for the rest of the connection — which is all of it.
        let settled = match &self.plan {
            None => true,
            Some(plan) => matches!(plan.state, SplitState::Through),
        };
        settled && self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HandshakeStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is a product decision, not an implementation detail: it decides what every
    /// installation puts on the wire. Changing it should take deleting this line.
    #[test]
    fn a_run_starts_on_the_strategy_that_was_measured_to_carry() {
        assert_eq!(selected(), Handshake::Fronted);
        assert_eq!(DEFAULT.name(), "fronted");
    }

    #[test]
    fn every_strategy_round_trips_through_its_written_name() {
        for handshake in Handshake::ALL {
            assert_eq!(Handshake::parse(handshake.name()), Some(handshake));
            assert_eq!(Handshake::from_code(handshake.code()), handshake);
        }
    }

    /// What each strategy names, on either carrier. `no-sni` is the one with none to send.
    /// Only a DNS name can stand in for the fronted one: an address in SNI is forbidden, and a
    /// refused name leaves the default in place rather than half-set.
    #[test]
    fn a_fronted_name_has_to_be_a_name() {
        assert!(set_fronted_name("162.159.198.1").is_err());
        assert!(set_fronted_name("not a name").is_err());
        assert!(set_fronted_name("").is_err());
        assert_eq!(fronted_name(), FRONTED_SNI.to_string());
    }

    #[test]
    fn each_strategy_names_what_it_says_it_names() {
        assert_eq!(Handshake::Named.sni(), Some(CONNECT_SNI.to_string()));
        assert_eq!(Handshake::Fronted.sni(), Some(FRONTED_SNI.to_string()));
        assert_eq!(Handshake::NoSni.sni(), None);
        assert!(Handshake::Fronted.works_over_quic());
        assert!(!Handshake::SplitSlow.works_over_quic());
    }

    #[test]
    fn an_unknown_name_is_refused_rather_than_defaulted() {
        assert_eq!(Handshake::parse("no-sni-please"), None);
        assert_eq!(Handshake::parse(""), None);
    }

    #[test]
    fn the_cut_lands_inside_the_name() {
        let needle = b"consumer-masque.cloudflareclient.com";
        let mut buffer = vec![0u8; 40];
        buffer.extend_from_slice(needle);
        buffer.extend_from_slice(&[0u8; 40]);

        let at = cut_point(&buffer, needle).expect("a buffer this size can be cut");
        assert!(at > 40, "the cut is past the start of the name");
        assert!(at < 40 + needle.len(), "the cut is before the end of it");
        // The point of the whole exercise: the first segment cannot carry the whole name.
        assert!(
            !buffer[..at].windows(needle.len()).any(|w| w == needle),
            "the name must not fit in the first segment"
        );
    }

    #[test]
    fn a_buffer_without_the_name_is_still_cut() {
        let buffer = vec![7u8; 64];
        assert_eq!(cut_point(&buffer, b"absent"), Some(32));
    }

    /// What the strategies actually put on the wire.
    ///
    /// The `no-sni` strategy rests entirely on rustls omitting the extension when the server name
    /// is an address, and `split` on the cut landing where it was aimed. Both are claims about
    /// bytes, so both are checked against bytes — a ClientHello written to a socket a test holds
    /// the other end of. The handshake never completes and is not meant to: everything under
    /// examination is in the client's first flight.
    ///
    /// One test rather than three, because the strategy is process-wide: three tests would race
    /// each other for it.
    #[tokio::test]
    async fn what_each_strategy_puts_on_the_wire() {
        use tokio::io::AsyncReadExt as _;
        use tokio::net::TcpListener;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let name = CONNECT_SNI.as_bytes();

        /// Accepts anything: this test is about what the client sends, not what a server says.
        #[derive(Debug)]
        struct AnyServer;
        impl rustls::client::danger::ServerCertVerifier for AnyServer {
            fn verify_server_cert(
                &self,
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &[rustls::pki_types::CertificateDer<'_>],
                _: &rustls::pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        let config = Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyServer))
                .with_no_client_auth(),
        );

        /// The bytes of the client's first flight, up to the first pause in it.
        async fn first_flight(config: Arc<rustls::ClientConfig>, how: Handshake) -> Vec<u8> {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a local port");
            let address = listener.local_addr().expect("the port it took");
            select(how);
            let client = tokio::spawn(async move {
                let tcp = TcpStream::connect(address)
                    .await
                    .expect("the listener is up");
                // Fails once the server has answered nothing; the ClientHello is already out.
                let _ = connect_tls(config, tcp, address.ip()).await;
            });

            let (mut accepted, _) = listener.accept().await.expect("the connection");
            let mut seen = vec![0u8; 4096];
            let read = accepted.read(&mut seen).await.expect("the first flight");
            seen.truncate(read);
            client.abort();
            seen
        }

        let control = first_flight(config.clone(), Handshake::Named).await;
        assert!(
            control.windows(name.len()).any(|w| w == name),
            "the named handshake sends the name in the clear — if this fails the check below              proves nothing"
        );

        let without = first_flight(config.clone(), Handshake::NoSni).await;
        assert!(
            !without.windows(name.len()).any(|w| w == name),
            "no-sni must put no name on the wire at all"
        );

        // The held-back half is what makes this readable as one segment: without the delay the
        // two writes can arrive together and a single read would show the whole name.
        let cut = first_flight(config, Handshake::SplitSlow).await;
        assert!(
            !cut.windows(name.len()).any(|w| w == name),
            "the first segment of a split handshake must not carry the whole name"
        );
        assert!(
            !cut.is_empty() && cut.len() < control.len(),
            "the first segment is a part of the flight, not all of it"
        );

        select(Handshake::Named);
    }

    /// The wrapper must not cost the connection its vectored writes.
    ///
    /// It is put there for one ClientHello and then stays under every packet the tunnel carries.
    /// A wrapper that answers "not vectored" turns each TLS record's header, payload and tag into
    /// a separate syscall, for the life of the connection — which is a real cost paid forever for
    /// a one-off trick, and it does not show up as a failure anywhere. It shows up as a tunnel
    /// that is slower than it was.
    #[tokio::test]
    async fn the_wrapper_keeps_vectored_writes() {
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a local port");
        let address = listener.local_addr().expect("the port it took");
        let bare = TcpStream::connect(address)
            .await
            .expect("the listener is up");
        let vectored = bare.is_write_vectored();
        assert!(
            vectored,
            "a TCP socket writes vectored, or this test proves nothing"
        );

        // No plan: the default strategy, and the one the tunnel actually runs on.
        let plain = HandshakeStream::wrapping(bare, Handshake::NoSni);
        assert!(
            plain.is_write_vectored(),
            "with nothing to split the wrapper must be transparent"
        );

        // A plan pending: the one case where the bytes have to be seen, so vectoring is given up
        // for exactly as long as that lasts.
        let bare = TcpStream::connect(address)
            .await
            .expect("the listener is up");
        let mut splitting = HandshakeStream::wrapping(bare, Handshake::Split);
        assert!(
            !splitting.is_write_vectored(),
            "a pending split has to see the bytes"
        );

        // And it lasts one write. After it, the connection is back to full speed.
        let (mut accepted, _) = listener.accept().await.expect("the connection");
        let mut hello = vec![0u8; 32];
        hello.extend_from_slice(CONNECT_SNI.as_bytes());
        hello.extend_from_slice(&[0u8; 32]);
        // The split deliberately hands back less than it was given, so the returned count is
        // checked rather than ignored.
        let sent = splitting.write(&hello).await.expect("the first segment");
        assert!(
            sent > 0 && sent < hello.len(),
            "the split writes part of the flight, not none of it and not all of it"
        );
        assert!(
            splitting.is_write_vectored(),
            "once the split is through the wrapper must step out of the way"
        );
        accepted.shutdown().await.ok();
    }

    #[test]
    fn a_buffer_too_small_to_cut_is_left_whole() {
        assert_eq!(cut_point(&[], b"absent"), None);
        assert_eq!(cut_point(&[1], b"absent"), None);
    }
}
