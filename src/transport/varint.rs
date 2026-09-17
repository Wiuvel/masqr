//! QUIC variable-length integers (RFC 9000 §16).
//!
//! Every length and type in both framings this core speaks is one of these: the capsules inside the
//! HTTP/2 stream, and the HTTP/3 frames, settings and datagram prefixes over QUIC.

use bytes::{BufMut, BytesMut};

/// The largest value the encoding can carry: 2^62 - 1.
pub const MAX: u64 = (1 << 62) - 1;

/// Write a QUIC variable-length integer.
///
/// The two most significant bits of the first byte give the length, so the value's magnitude picks
/// the encoding: one byte up to 63, two up to 16383, four up to 2^30-1, eight beyond that.
pub fn put(buf: &mut BytesMut, value: u64) {
    debug_assert!(value <= MAX, "{value} does not fit a varint");
    if value < 64 {
        buf.put_u8(value as u8);
    } else if value < 16_384 {
        buf.put_u16(0x4000 | value as u16);
    } else if value < 1 << 30 {
        buf.put_u32(0x8000_0000 | value as u32);
    } else {
        buf.put_u64(0xc000_0000_0000_0000 | value);
    }
}

/// How many bytes `put` will use for this value.
pub fn len(value: u64) -> usize {
    if value < 64 {
        1
    } else if value < 16_384 {
        2
    } else if value < 1 << 30 {
        4
    } else {
        8
    }
}

/// Read a QUIC variable-length integer, or `None` when the buffer does not hold a whole one yet.
///
/// Returns the value and how many bytes it occupied; the caller advances only once it has a whole
/// record, so a partial read leaves the buffer untouched.
pub fn get(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &buf[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every length class of the encoding, including the boundaries between them — those are where
    /// an off-by-one turns into a stream that never resynchronises.
    #[test]
    fn varints_round_trip_across_every_length_class() {
        for value in [0u64, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, MAX] {
            let mut buf = BytesMut::new();
            put(&mut buf, value);
            assert_eq!(buf.len(), len(value), "length disagrees for {value}");
            let (decoded, used) = get(&buf).expect("a whole varint");
            assert_eq!(decoded, value);
            assert_eq!(used, buf.len());
        }
    }

    /// The worked examples of RFC 9000 Appendix A.1, byte for byte.
    #[test]
    fn the_rfc_examples_decode_to_their_values() {
        for (bytes, value) in [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c][..],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d][..], 494_878_333),
            (&[0x7b, 0xbd][..], 15_293),
            (&[0x25][..], 37),
            // The same 37 in two bytes: the encoding does not have to be minimal.
            (&[0x40, 0x25][..], 37),
        ] {
            assert_eq!(get(bytes), Some((value, bytes.len())));
        }
    }

    #[test]
    fn a_varint_cut_short_is_not_read() {
        assert_eq!(get(&[]), None);
        assert_eq!(get(&[0x9d, 0x7f, 0x3e]), None);
    }
}
