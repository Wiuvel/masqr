//! The smallest packets that prove the path.
//!
//! Hand-built rather than taken from a crate: the checks need exactly these shapes, and building
//! them by hand keeps what is being proved visible.

/// An IPv4 packet carrying an ICMP echo request.
pub fn ipv4_icmp_echo(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(8); // echo request
    icmp.push(0); // code
    icmp.extend_from_slice(&[0, 0]); // checksum, filled in below
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let checksum = ones_complement(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let total_len = 20 + icmp.len();
    let mut packet = Vec::with_capacity(total_len);
    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0x40, 0]); // don't fragment
    packet.push(64);
    packet.push(1); // ICMP
    packet.extend_from_slice(&[0, 0]); // checksum, filled in below
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    let header_checksum = masqr::ip::ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet.extend_from_slice(&icmp);
    packet
}

/// The sequence number of an echo reply addressed back to us, or `None` for anything else.
pub fn icmp_echo_reply(packet: &[u8], ours: [u8; 4], id: u16) -> Option<u16> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 1 || packet[16..20] != ours {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let icmp = packet.get(header_len..)?;
    if icmp.len() < 8 || icmp[0] != 0 {
        return None; // not an echo reply
    }
    if u16::from_be_bytes([icmp[4], icmp[5]]) != id {
        return None;
    }
    Some(u16::from_be_bytes([icmp[6], icmp[7]]))
}

/// The internet checksum: one's complement of the one's-complement sum of 16-bit words.
fn ones_complement(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4 packet carrying UDP. The UDP checksum is left zero, which IPv4 allows and which means
/// "not computed" — the harness is proving the path, not the checksum.
pub fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = Vec::with_capacity(total_len);

    packet.push(0x45); // version 4, five words of header
    packet.push(0); // DSCP/ECN
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // identification
    packet.extend_from_slice(&[0x40, 0]); // don't fragment
    packet.push(64); // TTL — the tunnel decrements it on the way out
    packet.push(17); // UDP
    packet.extend_from_slice(&[0, 0]); // checksum, filled in below
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);

    let checksum = masqr::ip::ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet.extend_from_slice(&sport.to_be_bytes());
    packet.extend_from_slice(&dport.to_be_bytes());
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // checksum: optional over IPv4
    packet.extend_from_slice(payload);
    packet
}

/// The UDP payload of a reply addressed back to us, or `None` for anything else.
pub fn udp_payload(packet: &[u8], ours: [u8; 4]) -> Option<&[u8]> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if packet.len() < header_len + 8 || packet[16..20] != ours {
        return None;
    }
    Some(&packet[header_len + 8..])
}

/// A minimal A-record query.
pub fn dns_query(name: &str) -> Vec<u8> {
    let mut query = vec![0x2a, 0x2a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    query
}

/// The A records in a reply, as dotted quads. Anything it cannot walk yields nothing rather than
/// an error — this is a probe, and a reply it does not understand is simply not the answer.
pub fn dns_answers(message: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if message.len() < 12 {
        return out;
    }
    let questions = u16::from_be_bytes([message[4], message[5]]);
    let answers = u16::from_be_bytes([message[6], message[7]]);
    let mut at = 12;

    for _ in 0..questions {
        at = skip_name(message, at);
        at += 4;
    }
    for _ in 0..answers {
        at = skip_name(message, at);
        if at + 10 > message.len() {
            break;
        }
        let rtype = u16::from_be_bytes([message[at], message[at + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([message[at + 8], message[at + 9]]));
        at += 10;
        if at + rdlen > message.len() {
            break;
        }
        if rtype == 1 && rdlen == 4 {
            let a = &message[at..at + 4];
            out.push(format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]));
        }
        at += rdlen;
    }
    out
}

/// Step over a name, which is either labels ending in a zero byte or a two-byte pointer.
fn skip_name(message: &[u8], mut at: usize) -> usize {
    while at < message.len() {
        let len = message[at];
        if len & 0xc0 == 0xc0 {
            return at + 2;
        }
        at += 1;
        if len == 0 {
            return at;
        }
        at += usize::from(len);
    }
    at
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: [u8; 4] = [172, 16, 0, 2];
    const THEM: [u8; 4] = [1, 1, 1, 1];

    /// What the far side sends back for an echo: the same message with the addresses swapped and
    /// the type turned into a reply.
    fn reply_to(request: &[u8]) -> Vec<u8> {
        let mut reply = request.to_vec();
        reply[12..16].copy_from_slice(&THEM);
        reply[16..20].copy_from_slice(&US);
        reply[20] = 0;
        reply
    }

    /// A checksum a receiver rejects makes every echo look like a path that swallows them.
    #[test]
    fn an_echo_request_carries_checksums_that_verify() {
        let packet = ipv4_icmp_echo(US, THEM, 0x6d71, 7, &[0x5a; 64]);
        // Summed with its own checksum in place, a correct header or message comes to zero.
        assert_eq!(ones_complement(&packet[..20]), 0);
        assert_eq!(ones_complement(&packet[20..]), 0);
        assert_eq!(
            usize::from(u16::from_be_bytes([packet[2], packet[3]])),
            packet.len()
        );
    }

    #[test]
    fn only_a_reply_to_this_run_is_counted() {
        let request = ipv4_icmp_echo(US, THEM, 0x6d71, 7, &[0x5a; 64]);
        assert_eq!(icmp_echo_reply(&reply_to(&request), US, 0x6d71), Some(7));
        assert_eq!(icmp_echo_reply(&reply_to(&request), US, 0x0001), None);
        assert_eq!(icmp_echo_reply(&reply_to(&request), THEM, 0x6d71), None);
        // The request itself, looped back, is not an answer.
        assert_eq!(icmp_echo_reply(&request, THEM, 0x6d71), None);
    }

    #[test]
    fn an_answer_is_read_through_a_compressed_name() {
        let query = dns_query("cloudflare.com");
        let mut message = query.clone();
        message[2] |= 0x80;
        message[7] = 2;
        for address in [[104, 16, 132, 229], [104, 16, 133, 229]] {
            // A pointer to the question's name, then A, IN, a TTL, and four bytes of address.
            message.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4]);
            message.extend_from_slice(&address);
        }
        let packet = ipv4_udp(THEM, US, 53, 40000, &message);

        let payload = udp_payload(&packet, US).expect("addressed to us");
        assert_eq!(
            dns_answers(payload),
            vec!["104.16.132.229", "104.16.133.229"]
        );
        assert_eq!(udp_payload(&packet, THEM), None);
        assert!(dns_answers(&message[..message.len() - 3]).len() == 1);
    }
}
