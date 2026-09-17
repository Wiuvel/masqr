//! The CONNECT-IP tunnel as the engine sees it: packets out, packets back, and whether the far end
//! is still there — over whichever carrier opened.
//!
//! Two carriers speak CONNECT-IP to the same endpoint with the same identity: HTTP/3 over QUIC
//! (`quic.rs`) and HTTP/2 over TCP (`tcp.rs`). Which one an attempt tries is `carrier.rs`'s
//! decision. Each half here is the one or the other, and everything above this module drives them
//! the same way; the carrier shows only where it is reported.

use std::time::{Duration, Instant};

use bytes::Bytes;

use super::carrier::{self, Carrier, Plan};
use super::http3::H3Error;
use super::{quic, tcp};
use crate::ip::ipv4_checksum;
use crate::warp::Identity;

#[derive(Debug, thiserror::Error)]
/// Why a tunnel could not be opened, or stopped carrying.
pub enum ConnectError {
    #[error("tls setup: {0}")]
    TlsSetup(#[from] super::tls::TlsSetupError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http/2: {0}")]
    H2(#[from] h2::Error),
    #[error("building the connect request: {0}")]
    Request(#[from] http::Error),
    /// The endpoint declined the request over HTTP/2. The one refusal read as being about the
    /// device — see `refusal_is_about_the_device`.
    #[error("the endpoint refused the tunnel with {0}")]
    Refused(http::StatusCode),
    #[error("the endpoint address {0} is not an address")]
    BadEndpoint(String),
    #[error("the tunnel was closed while a packet was waiting to be sent")]
    Closed,
    #[error("{0}")]
    Framing(#[from] super::capsule::TooLong),
    /// The most common failure in the field, and the one an unexplained end-of-file explains
    /// worst.
    ///
    /// Which handshake was tried is part of the message, because with the default one the fix is
    /// not in this core — a bypass has to be running underneath — while with any other it is the
    /// result of the experiment.
    #[error(
        "the TLS handshake ({how}, name {sni}) was cut with no reply. On a filtered link that is what a blocked name looks like"
    )]
    HandshakeCut { sni: String, how: &'static str },
    /// No QUIC connection: UDP to the endpoint dropped, or the handshake refused.
    #[error("QUIC to the endpoint did not come up: {0}")]
    QuicUnavailable(String),
    /// HTTP/3's form of [`ConnectError::HandshakeCut`]: the handshake completed, and then nothing
    /// came back — no SETTINGS, or no answer to the CONNECT. Measured on a filtered link, that is
    /// what a blocked name in the Initial looks like.
    #[error(
        "the endpoint took the QUIC handshake ({how}, name {sni}) and then answered nothing. On a filtered link that is what a blocked name looks like"
    )]
    H3Unanswered { sni: String, how: &'static str },
    /// The endpoint declined the request over HTTP/3.
    ///
    /// Kept apart from [`ConnectError::Refused`] on purpose. A refusal there replaces the device,
    /// and a status that is really about the HTTP/3 request — a header the endpoint stopped
    /// accepting — would then register a new device every few minutes without fixing anything.
    /// Under `auto`, HTTP/2 is tried next, and its answer is the one that speaks for the device.
    #[error("the endpoint refused the tunnel over HTTP/3 with {0}")]
    H3Refused(http::StatusCode),
    /// The connection is up but cannot carry this adapter's packets.
    #[error("HTTP/3 cannot carry this adapter's packets: {0}")]
    H3Unfit(String),
    #[error("quic: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("writing the request: {0}")]
    QuicWrite(#[from] quinn::WriteError),
    #[error("reading the tunnel's stream: {0}")]
    QuicRead(#[from] quinn::ReadError),
    #[error("http/3: {0}")]
    H3(#[from] H3Error),
    #[error("the endpoint is shutting the connection down (GOAWAY)")]
    GoingAway,
}

impl ConnectError {
    /// Whether this is something on the way refusing the handshake: the one failure that says the
    /// fix is not in this core.
    pub fn is_blocked(&self) -> bool {
        matches!(
            self,
            ConnectError::HandshakeCut { .. } | ConnectError::H3Unanswered { .. }
        )
    }
}

/// A live CONNECT-IP tunnel: one direction to write packets into, one to read them from.
///
/// The two directions are separate values rather than two methods on one, because they are pumped
/// by two different tasks: nothing carries packets back while a task waits for the room to send
/// one, and vice versa.
pub struct Tunnel {
    pub sender: TunnelSender,
    pub receiver: TunnelReceiver,
    pub health: TunnelHealth,
}

/// The half that carries packets out.
pub enum TunnelSender {
    H2(tcp::Sender),
    H3(quic::Sender),
}

/// The half that carries packets back.
pub enum TunnelReceiver {
    H2(tcp::Receiver),
    H3(quic::Receiver),
}

/// Whether the connection under the tunnel is still answering.
///
/// A tunnel does not always fail by closing. A link that goes away underneath one leaves a
/// connection that is neither closed nor working, and traffic alone cannot tell that apart from a
/// quiet moment, so the question is asked directly.
pub enum TunnelHealth {
    H2(tcp::Health),
    H3(quic::Health),
}

/// How long each stage of bringing the tunnel up took.
///
/// Several numbers rather than one, because the stages fail for entirely different reasons: the
/// link, the filtering, the endpoint, the identity. A single "connect took N ms" would say which
/// of them was slow only by accident.
#[derive(Debug, Clone, Copy)]
pub enum Stages {
    H2 {
        tcp_ms: u128,
        tls_ms: u128,
        http2_ms: u128,
        connect_ms: u128,
    },
    H3 {
        /// The QUIC handshake, TLS inside it.
        quic_ms: u128,
        /// This side's SETTINGS out and the endpoint's back.
        settings_ms: u128,
        /// The CONNECT and its answer, then the wait for the path to fit a full packet.
        connect_ms: u128,
    },
}

impl Stages {
    pub fn carrier(&self) -> Carrier {
        match self {
            Stages::H2 { .. } => Carrier::H2,
            Stages::H3 { .. } => Carrier::H3,
        }
    }

    /// Each stage by name, in the order they happened.
    pub fn steps(&self) -> Vec<(&'static str, u128)> {
        match *self {
            Stages::H2 {
                tcp_ms,
                tls_ms,
                http2_ms,
                connect_ms,
            } => vec![
                ("tcp", tcp_ms),
                ("tls", tls_ms),
                ("http2", http2_ms),
                ("connect", connect_ms),
            ],
            Stages::H3 {
                quic_ms,
                settings_ms,
                connect_ms,
            } => vec![
                ("quic", quic_ms),
                ("settings", settings_ms),
                ("connect", connect_ms),
            ],
        }
    }
}

impl std::fmt::Display for Stages {
    /// `h3 · quic 61 · settings 1 · connect 74`
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.carrier().name())?;
        for (name, ms) in self.steps() {
            write!(f, " · {name} {ms}")?;
        }
        Ok(())
    }
}

/// Open the tunnel over the carrier the run chose.
///
/// Under `auto` this is HTTP/3, and HTTP/2 in the same attempt when HTTP/3 does not open — the
/// failure is said once, and HTTP/3 is parked so the next attempts do not pay for it again. See
/// carrier.rs.
pub async fn connect(identity: &Identity) -> Result<(Tunnel, Stages), ConnectError> {
    let now = Instant::now();
    let plan = carrier::plan(
        carrier::selected(),
        super::handshake::selected(),
        carrier::parked(now),
    );
    match plan {
        Plan::Only(Carrier::H2) => tcp::connect(identity).await,
        Plan::Only(Carrier::H3) => quic::connect(identity).await,
        Plan::H3ThenH2 => match quic::connect(identity).await {
            Ok(opened) => Ok(opened),
            Err(problem) => {
                carrier::park(Instant::now());
                notice!(
                    "tunnel",
                    "HTTP/3 did not open ({problem}); carrying over HTTP/2. HTTP/3 is tried again \
                     when the line changes, on a reconnect, or in {} min",
                    carrier::PARK_FOR.as_secs() / 60
                );
                tcp::connect(identity).await
            }
        },
    }
}

/// Open the tunnel over HTTP/3 alone, for a tunnel over HTTP/2 that is looking to move to it.
pub async fn connect_h3(identity: &Identity) -> Result<(Tunnel, Stages), ConnectError> {
    quic::connect(identity).await
}

impl Tunnel {
    /// The three parts, to be driven independently: packets out, packets back, and the question of
    /// whether the connection carrying them is still there.
    pub fn split(self) -> (TunnelSender, TunnelReceiver, TunnelHealth) {
        (self.sender, self.receiver, self.health)
    }

    /// Send one IP packet.
    pub async fn send(&mut self, packet: Vec<u8>) -> Result<(), ConnectError> {
        self.sender.send(&mut [packet]).await
    }

    /// Receive one IP packet, or `None` once the endpoint closed the tunnel.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, ConnectError> {
        self.receiver.recv().await
    }
}

impl TunnelSender {
    /// Send a run of IP packets in the order given, waiting for the room to do so.
    ///
    /// The packets are passed as owned bytes because the hop count is decremented in place: a
    /// router that forwarded packets without doing so would let a loop run forever.
    pub async fn send(&mut self, packets: &mut [Vec<u8>]) -> Result<(), ConnectError> {
        match self {
            TunnelSender::H2(sender) => sender.send(packets).await,
            TunnelSender::H3(sender) => sender.send(packets).await,
        }
    }
}

impl TunnelReceiver {
    /// Receive one IP packet, or `None` once the endpoint closed the tunnel.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, ConnectError> {
        match self {
            TunnelReceiver::H2(receiver) => receiver.recv().await,
            TunnelReceiver::H3(receiver) => receiver.recv().await,
        }
    }
}

/// What QUIC reports about an HTTP/3 connection's path.
///
/// Reported beside the packets handed to the adapter, because the two together answer the question
/// a loss under load raises: `datagrams_in` counts what reached this side, so a gap between it and
/// what the adapter was given is this side's buffer, and `lost` is the path's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStats {
    pub rtt: Duration,
    /// Congestion window, bytes.
    pub cwnd: u64,
    /// QUIC packets sent on the path, and how many of them were declared lost.
    pub sent: u64,
    pub lost: u64,
    /// DATAGRAM frames received, whatever became of them afterwards.
    pub datagrams_in: u64,
}

impl TunnelHealth {
    /// The path as QUIC sees it, over HTTP/3. HTTP/2 has no counterpart: TCP keeps its own counts.
    pub fn link_stats(&self) -> Option<LinkStats> {
        match self {
            TunnelHealth::H2(_) => None,
            TunnelHealth::H3(health) => Some(health.link_stats()),
        }
    }

    /// Ask whether the endpoint still answers, and how long a round trip takes.
    ///
    /// The time is what the queue in front of the tunnel works its delay target to. Over HTTP/3 it
    /// is QUIC's estimate from acknowledgements; over HTTP/2 it is a ping that waited behind the
    /// TCP send buffer, which under load measures the buffer as much as the link.
    pub async fn probe(&mut self) -> Result<Duration, ConnectError> {
        match self {
            TunnelHealth::H2(health) => health.probe().await,
            TunnelHealth::H3(health) => health.probe().await,
        }
    }
}

/// Decrement TTL (v4) or hop limit (v6), fixing the IPv4 header checksum. False when the packet is
/// malformed or its hop count is already spent.
pub(super) fn decrement_hop_limit(packet: &mut [u8]) -> bool {
    match packet.first().map(|b| b >> 4) {
        Some(4) => {
            // The header is as long as the packet says it is. Summing a fixed twenty bytes
            // leaves any options out, and a checksum that does not cover the whole header is
            // rejected by the destination: the packet is forwarded here and discarded there.
            // Options are rare, which is why it survived this long undetected.
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20 || packet.len() < header || packet[8] <= 1 {
                return false;
            }
            packet[8] -= 1;
            let checksum = ipv4_checksum(&packet[..header]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            true
        }
        Some(6) => {
            if packet.len() < 40 || packet[7] <= 1 {
                return false;
            }
            packet[7] -= 1;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checked by the property the checksum is defined by, not against a number written down by
    /// hand: with the computed value in place, the ones' complement sum over the WHOLE header —
    /// checksum field included — is 0xffff. A receiver checks it exactly this way.
    #[test]
    fn a_computed_checksum_makes_the_header_verify() {
        let mut header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let checksum = ipv4_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());

        let mut sum = 0u32;
        for pair in header.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff, "the header does not verify");
    }

    #[test]
    fn decrementing_ttl_keeps_the_checksum_valid() {
        let mut packet: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb8, 0x61, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        assert!(decrement_hop_limit(&mut packet));
        assert_eq!(packet[8], 0x3f);
        // Recomputing over the new header must reproduce the checksum that was just written.
        let written = u16::from_be_bytes([packet[10], packet[11]]);
        assert_eq!(ipv4_checksum(&packet[..20]), written);
    }

    /// The same, for a header carrying options — the case a fixed twenty-byte sum gets wrong.
    ///
    /// Rare on the wire, which is why it mattered: a packet with a Router Alert or a timestamp
    /// left here with a checksum covering only part of its header and was dropped at the far end,
    /// with nothing on this side to say so.
    #[test]
    fn a_header_with_options_is_summed_whole() {
        // IHL 6: twenty bytes of header and one four-byte option (Router Alert).
        let mut packet: Vec<u8> = vec![
            0x46, 0x00, 0x00, 0x40, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c, 0x94, 0x04, 0x00, 0x00,
        ];
        let sum = ipv4_checksum(&packet[..24]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());

        assert!(decrement_hop_limit(&mut packet));
        assert_eq!(packet[8], 0x3f);
        let written = u16::from_be_bytes([packet[10], packet[11]]);
        assert_eq!(
            ipv4_checksum(&packet[..24]),
            written,
            "the option bytes were left out of the sum"
        );
    }

    /// A header shorter than it claims is refused rather than read past.
    #[test]
    fn a_header_longer_than_the_packet_is_refused() {
        let mut packet = vec![0x46u8; 20]; // says twenty-four bytes, carries twenty
        packet[8] = 64;
        assert!(!decrement_hop_limit(&mut packet));
    }

    /// A packet that has run out of hops is dropped rather than forwarded with a wrapped TTL.
    #[test]
    fn a_spent_hop_count_is_refused() {
        let mut v4 = vec![0x45u8; 20];
        v4[8] = 1;
        assert!(!decrement_hop_limit(&mut v4));

        let mut v6 = vec![0x60u8; 40];
        v6[7] = 0;
        assert!(!decrement_hop_limit(&mut v6));
    }

    #[test]
    fn a_truncated_packet_is_refused_rather_than_indexed_into() {
        assert!(!decrement_hop_limit(&mut [0x45, 0x00]));
        assert!(!decrement_hop_limit(&mut [0x60, 0x00]));
        assert!(!decrement_hop_limit(&mut []));
    }

    /// The two failures that mean something on the way refused the handshake, one per carrier,
    /// and nothing else.
    #[test]
    fn only_a_cut_or_unanswered_handshake_reads_as_blocked() {
        let cut = ConnectError::HandshakeCut {
            sni: "www.cloudflare.com".to_string(),
            how: "fronted",
        };
        let unanswered = ConnectError::H3Unanswered {
            sni: "www.cloudflare.com".to_string(),
            how: "fronted",
        };
        assert!(cut.is_blocked());
        assert!(unanswered.is_blocked());
        assert!(!ConnectError::QuicUnavailable("no answer within 4 s".into()).is_blocked());
        assert!(!ConnectError::H3Refused(http::StatusCode::FORBIDDEN).is_blocked());
    }

    #[test]
    fn stages_say_which_carrier_and_each_step() {
        let h3 = Stages::H3 {
            quic_ms: 61,
            settings_ms: 1,
            connect_ms: 74,
        };
        assert_eq!(h3.to_string(), "h3 · quic 61 · settings 1 · connect 74");
        let h2 = Stages::H2 {
            tcp_ms: 21,
            tls_ms: 64,
            http2_ms: 3,
            connect_ms: 80,
        };
        assert_eq!(h2.carrier(), Carrier::H2);
        assert_eq!(h2.steps()[0], ("tcp", 21));
    }
}
