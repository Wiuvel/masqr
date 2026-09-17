//! Measuring whether the tunnel carries IPv6.
//!
//! Assuming it does is the expensive mistake. Nothing here resolves on a program's behalf: Windows
//! races the address families itself, using the routing table to decide what is reachable. A v6
//! prefix routed into a tunnel that drops v6 tells Windows the faster-looking path exists, and
//! every connection then waits out its own fallback — the family that works ends up slower than
//! before the tunnel existed. See `docs/design/decisions.md`.
//!
//! One DNS query over the live tunnel is the smallest exchange that proves the path: one datagram
//! out, one back, no handshake state.
//!
//! The UDP checksum below is computed rather than zeroed. Over IPv6 it is not optional, and a
//! datagram carrying a wrong one is discarded without a reply.

use std::net::Ipv6Addr;
use std::time::Duration;

use crate::transport::Tunnel;

/// How long to wait for the answer before deciding there is none.
///
/// Short: this runs between the tunnel coming up and traffic starting to move, so every millisecond
/// spent here is a millisecond the machine spends waiting. An exit that has not answered in two
/// seconds is not an exit that is about to.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Who is asked. A resolver reachable over IPv6 from anywhere the tunnel could plausibly exit, and
/// one the endpoint operates itself, so the answer describes the tunnel rather than the internet.
const PROBE_RESOLVER: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

/// The name asked about. Any name would do; this one is short, and it is the endpoint's own.
const PROBE_NAME: &str = "cloudflare.com";

/// The source port. Arbitrary, and only ever compared against what comes back.
const PROBE_PORT: u16 = 40_001;

/// Next-header value for UDP, in both the header and the checksum's pseudo-header.
const NEXT_HEADER_UDP: u8 = 17;

/// Ask the tunnel to carry one IPv6 datagram, and say whether anything came back.
///
/// A false answer is not a failure of the tunnel. Plenty of exits carry v4 only, and the right
/// response is to leave v6 on the line rather than to refuse to run.
pub async fn carries_ipv6(tunnel: &mut Tunnel, source: Ipv6Addr) -> bool {
    let packet = dns_over_ipv6(source, PROBE_RESOLVER, PROBE_PORT, PROBE_NAME);
    if tunnel.send(packet).await.is_err() {
        return false;
    }

    // A handful, not one: the tunnel carries whatever the endpoint sends, and an unrelated packet
    // arriving first is not an answer to this question either way.
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    loop {
        let waited = tokio::time::timeout_at(deadline, tunnel.recv()).await;
        match waited {
            Ok(Ok(Some(reply))) if is_reply_to(&reply, source, PROBE_PORT) => return true,
            // Something else came back. Keep waiting: the deadline, not the packet, is what ends
            // this.
            Ok(Ok(Some(_))) => continue,
            _ => return false,
        }
    }
}

/// An IPv6 packet carrying a UDP DNS query.
///
/// The checksum is computed and not skipped. Over IPv4 a zero UDP checksum means "not computed" and
/// is accepted; over IPv6 there is no such licence, and a datagram with the wrong one is dropped
/// silently — which would read here as "the tunnel does not carry v6", and would be wrong.
fn dns_over_ipv6(source: Ipv6Addr, destination: Ipv6Addr, port: u16, name: &str) -> Vec<u8> {
    let query = dns_query(name);
    let udp_len = 8 + query.len();

    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&port.to_be_bytes());
    udp.extend_from_slice(&53u16.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum, filled in below
    udp.extend_from_slice(&query);

    let checksum = udp_checksum(source, destination, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut packet = Vec::with_capacity(40 + udp_len);
    packet.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, no traffic class, no flow label
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.push(NEXT_HEADER_UDP);
    packet.push(64); // hop limit; the tunnel decrements it on the way out
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(&udp);
    packet
}

/// The UDP checksum over IPv6: the pseudo-header, then the datagram.
///
/// The pseudo-header is the two addresses, the upper-layer length as four bytes, three zero bytes
/// and the next-header value. It is not transmitted; it exists so that a datagram delivered to the
/// wrong address fails to verify rather than being accepted by whoever received it.
fn udp_checksum(source: Ipv6Addr, destination: Ipv6Addr, datagram: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut add = |bytes: &[u8]| {
        let mut pairs = bytes.chunks_exact(2);
        for pair in &mut pairs {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        // An odd length is padded on the right with a zero byte, which is what the definition says
        // and what a datagram of odd length needs.
        if let [last] = pairs.remainder() {
            sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
    };

    add(&source.octets());
    add(&destination.octets());
    add(&(datagram.len() as u32).to_be_bytes());
    add(&[0, 0, 0, NEXT_HEADER_UDP]);
    add(datagram);

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = !(sum as u16);
    // Zero would mean "no checksum", which over IPv6 is not a thing a sender may say. The
    // definition reserves the all-ones form for a checksum that computes to zero.
    if folded == 0 { 0xffff } else { folded }
}

/// Whether a packet is a UDP datagram addressed back to us on the port we asked from.
fn is_reply_to(packet: &[u8], us: Ipv6Addr, port: u16) -> bool {
    // Forty bytes of header, eight of UDP.
    if packet.len() < 48 || packet[0] >> 4 != 6 || packet[6] != NEXT_HEADER_UDP {
        return false;
    }
    let destination: [u8; 16] = match packet[24..40].try_into() {
        Ok(octets) => octets,
        Err(_) => return false,
    };
    if Ipv6Addr::from(destination) != us {
        return false;
    }
    u16::from_be_bytes([packet[42], packet[43]]) == port
}

/// A minimal A-record query. The transaction id is fixed: nothing here reads it back, and the
/// question being asked is whether a packet returns at all.
fn dns_query(name: &str) -> Vec<u8> {
    let mut query = vec![0x2a, 0x2a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> Ipv6Addr {
        "2606:4700:110:8118:f6ab:31b0:1bd1:d8a".parse().unwrap()
    }

    /// Checked by the property a checksum is defined by rather than against a number written down
    /// by hand: recomputing over the datagram with the value in place, and over the same
    /// pseudo-header, sums to all ones. That is exactly what the receiver does.
    #[test]
    fn the_checksum_makes_the_datagram_verify() {
        let packet = dns_over_ipv6(source(), PROBE_RESOLVER, PROBE_PORT, PROBE_NAME);
        let datagram = &packet[40..];

        let mut sum = 0u32;
        for field in [
            &source().octets()[..],
            &PROBE_RESOLVER.octets()[..],
            &(datagram.len() as u32).to_be_bytes()[..],
            &[0, 0, 0, NEXT_HEADER_UDP][..],
            datagram,
        ] {
            let mut pairs = field.chunks_exact(2);
            for pair in &mut pairs {
                sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
            }
            if let [last] = pairs.remainder() {
                sum += u32::from(u16::from_be_bytes([*last, 0]));
            }
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff, "the datagram does not verify");
    }

    /// Over IPv6 a zero checksum is not a legal thing to send. A datagram whose checksum computes
    /// to zero is sent as all ones instead, and this is the one case where that matters.
    #[test]
    fn a_checksum_that_computes_to_zero_is_sent_as_all_ones() {
        // A datagram chosen so the ones' complement sum is already all ones, which complements to
        // zero. Any such input must come back as 0xffff rather than 0.
        let ones = udp_checksum(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED, &[0xff, 0xff]);
        assert_ne!(ones, 0, "zero would mean the sender computed none");
    }

    #[test]
    fn the_packet_is_a_well_formed_ipv6_udp_datagram() {
        let packet = dns_over_ipv6(source(), PROBE_RESOLVER, PROBE_PORT, PROBE_NAME);

        assert_eq!(packet[0] >> 4, 6, "version");
        assert_eq!(packet[6], NEXT_HEADER_UDP, "next header");
        let payload = u16::from_be_bytes([packet[4], packet[5]]);
        assert_eq!(usize::from(payload), packet.len() - 40, "payload length");
        assert_eq!(&packet[8..24], &source().octets(), "source");
        assert_eq!(&packet[24..40], &PROBE_RESOLVER.octets(), "destination");
        assert_eq!(u16::from_be_bytes([packet[40], packet[41]]), PROBE_PORT);
        assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), 53);
    }

    /// The reply test is what decides the whole question, so it has to refuse everything that is
    /// not an answer: another protocol, another address, another port, or something too short to
    /// hold any of them.
    #[test]
    fn only_a_datagram_addressed_back_to_us_counts_as_an_answer() {
        let mut reply = vec![0u8; 48];
        reply[0] = 0x60;
        reply[6] = NEXT_HEADER_UDP;
        reply[24..40].copy_from_slice(&source().octets());
        reply[42..44].copy_from_slice(&PROBE_PORT.to_be_bytes());
        assert!(is_reply_to(&reply, source(), PROBE_PORT));

        let mut other_port = reply.clone();
        other_port[42..44].copy_from_slice(&9u16.to_be_bytes());
        assert!(!is_reply_to(&other_port, source(), PROBE_PORT));

        let mut other_address = reply.clone();
        other_address[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        assert!(!is_reply_to(&other_address, source(), PROBE_PORT));

        let mut other_protocol = reply.clone();
        other_protocol[6] = 58; // an ICMPv6 message, which is not an answer to a query
        assert!(!is_reply_to(&other_protocol, source(), PROBE_PORT));

        let mut v4 = reply.clone();
        v4[0] = 0x45;
        assert!(!is_reply_to(&v4, source(), PROBE_PORT));

        for cut in 0..48 {
            assert!(!is_reply_to(&reply[..cut], source(), PROBE_PORT), "{cut}");
        }
    }
}
