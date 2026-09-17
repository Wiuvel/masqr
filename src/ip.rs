//! Ones'-complement arithmetic over IP headers.
//!
//! The same fold was written out four times: the IPv4 header checksum in the packet path, an
//! identical copy in the diagnostics, the ICMP checksum, and the IPv6 pseudo-header sum. Two of
//! them were byte-for-byte the same function.

/// A running ones'-complement sum.
///
/// Separate from the fold because the IPv6 pseudo-header is summed from pieces that are never
/// contiguous in memory — two addresses, a length and a next-header byte, then the datagram.
#[derive(Default)]
pub(crate) struct Sum(u32);

impl Sum {
    /// Add a run of bytes. An odd length is padded on the right with a zero byte, as the definition
    /// requires.
    pub(crate) fn add(&mut self, bytes: &[u8]) {
        let mut pairs = bytes.chunks_exact(2);
        for pair in &mut pairs {
            self.0 += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let [last] = pairs.remainder() {
            self.0 += u32::from(u16::from_be_bytes([*last, 0]));
        }
    }

    /// The carries folded in and the result inverted: the value a checksum field carries.
    pub(crate) fn fold(self) -> u16 {
        let mut sum = self.0;
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// The checksum of a run of bytes, for a header that carries no checksum field of its own.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = Sum::default();
    sum.add(bytes);
    sum.fold()
}

/// The IPv4 header checksum: the whole header, with the checksum field itself read as zero.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = Sum::default();
    for (at, pair) in header.chunks_exact(2).enumerate() {
        // Bytes 10..12 are the field being computed.
        if at != 5 {
            sum.add(pair);
        }
    }
    sum.fold()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_verifies_against_its_own_checksum() {
        // Summing a header that already carries a correct checksum gives all ones, which is how a
        // receiver checks one.
        let mut header: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let sum = ipv4_checksum(&header);
        header[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(checksum(&header), 0);
    }

    #[test]
    fn an_odd_length_is_padded_on_the_right() {
        // The last byte is the high half of a word, not the low one. Getting this backwards
        // produces a checksum that verifies here and nowhere else.
        assert_eq!(checksum(&[0x12]), checksum(&[0x12, 0x00]));
        assert_ne!(checksum(&[0x12]), checksum(&[0x00, 0x12]));
    }

    #[test]
    fn carries_are_folded_rather_than_dropped() {
        // Two words that overflow sixteen bits: the carry has to come back round.
        let mut sum = Sum::default();
        sum.add(&[0xff, 0xff]);
        sum.add(&[0x00, 0x01]);
        assert_eq!(sum.fold(), 0xfffe);
    }
}
