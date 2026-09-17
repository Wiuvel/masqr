//! HTTP capsules: how IP packets travel inside the HTTP/2 stream.
//!
//! Over QUIC, CONNECT-IP uses real datagrams (see quic.rs). Over HTTP/2 there are none, so the
//! tunnel borrows the capsule protocol: the body is an endless stream of `type · length · payload`
//! records, and type 0 carries one IP packet. Both numbers are QUIC variable-length integers, so a
//! small packet costs two bytes of framing.
//!
//! Nothing here knows about IP.

use bytes::{Buf, BufMut, BytesMut};

use super::varint;

/// The capsule type that carries a datagram. The only one this tunnel sends or reads.
pub const DATAGRAM: u64 = 0;

/// The largest capsule this tunnel will wait for.
///
/// A length is a number the other end writes, and the varint encoding lets it write one up to
/// 2^62. Without a ceiling, a stream declaring such a length would have this side buffering every
/// byte that arrived until the whole of it was there — which is never — while flow control kept
/// reopening the window for more. That is unbounded memory on the strength of a number, and the
/// number costs the sender eight bytes.
///
/// Sixty-five kilobytes is larger than any packet a tunnel with a 1280-byte MTU carries, so the
/// ceiling cannot be reached by anything this tunnel exists for.
pub const MAX_CAPSULE: u64 = 65_535;

/// Frame one datagram as a capsule.
pub fn encode_datagram(payload: &[u8]) -> BytesMut {
    let mut out = BytesMut::with_capacity(
        varint::len(DATAGRAM) + varint::len(payload.len() as u64) + payload.len(),
    );
    encode_datagram_into(&mut out, payload);
    out
}

/// The same capsule, appended to a buffer that already holds others.
///
/// What this is for: several packets written as one run rather than one apiece. The stream does not
/// care where one capsule ends and the next begins, so a run of them is one write instead of one
/// per packet — and on the way out that is one TLS record and one system call rather than several.
pub fn encode_datagram_into(out: &mut BytesMut, payload: &[u8]) {
    out.reserve(varint::len(DATAGRAM) + varint::len(payload.len() as u64) + payload.len());
    varint::put(out, DATAGRAM);
    varint::put(out, payload.len() as u64);
    out.put_slice(payload);
}

/// Pull one whole capsule out of `buf`, or `None` if it has not all arrived.
///
/// A capsule of a type this tunnel does not carry is consumed and reported as `Some(None)`. The
/// stream has to stay in sync even for records nothing reads, and treating them as an error would
/// tear down a healthy tunnel over a message it was free to ignore.
#[allow(clippy::type_complexity)]
pub fn take_capsule(buf: &mut BytesMut) -> Result<Option<Option<BytesMut>>, TooLong> {
    let Some((capsule_type, type_len)) = varint::get(buf) else {
        return Ok(None);
    };
    let Some((payload_len, len_len)) = varint::get(&buf[type_len..]) else {
        return Ok(None);
    };
    if payload_len > MAX_CAPSULE {
        return Err(TooLong(payload_len));
    }
    let total = type_len + len_len + payload_len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    buf.advance(type_len + len_len);
    let payload = buf.split_to(payload_len as usize);
    Ok(Some((capsule_type == DATAGRAM).then_some(payload)))
}

/// A capsule longer than anything this tunnel carries.
///
/// The stream cannot be resynchronised past one — a capsule's length is how the next one's start is
/// found — so this ends the tunnel rather than skipping anything, and the engine opens another.
#[derive(Debug, thiserror::Error)]
#[error(
    "the endpoint declared a capsule of {0} bytes, which no packet this tunnel carries reaches"
)]
pub struct TooLong(pub u64);

#[cfg(test)]
mod tests {
    use super::*;

    /// One capsule out of the stream, for a test that is about something other than the shape of
    /// the answer. `Err` and "not yet whole" are told apart where each of them is the subject.
    fn taken(buf: &mut BytesMut) -> Option<Option<BytesMut>> {
        take_capsule(buf).expect("a length within the ceiling")
    }

    #[test]
    fn a_datagram_survives_the_round_trip() {
        let packet = b"\x45\x00\x00\x28 and the rest of a packet";
        let mut stream = encode_datagram(packet);
        let one = taken(&mut stream).expect("whole").expect("a datagram");
        assert_eq!(&one[..], packet);
        assert!(stream.is_empty());
    }

    /// The stream arrives in whatever pieces the network chose, so a decoder that assumed whole
    /// capsules would lose data on the first split header.
    #[test]
    fn a_capsule_split_across_reads_is_not_consumed_early() {
        let packet = vec![0x45u8; 300];
        let whole = encode_datagram(&packet);

        let mut buf = BytesMut::new();
        for cut in [1usize, 2, 3, 100] {
            buf.extend_from_slice(&whole[..cut]);
            assert!(taken(&mut buf).is_none(), "acted on {cut} bytes");
            buf.clear();
        }

        buf.extend_from_slice(&whole);
        assert_eq!(taken(&mut buf).unwrap().unwrap().len(), packet.len());
    }

    /// An unknown capsule type is skipped rather than raised: the stream stays in sync, and the
    /// datagram behind it is still read.
    #[test]
    fn an_unknown_capsule_is_skipped_without_losing_the_next_one() {
        let mut buf = BytesMut::new();
        varint::put(&mut buf, 42);
        varint::put(&mut buf, 3);
        buf.put_slice(b"xyz");
        buf.extend_from_slice(&encode_datagram(b"packet"));

        assert!(taken(&mut buf).expect("whole").is_none());
        assert_eq!(&taken(&mut buf).unwrap().unwrap()[..], b"packet");
    }

    /// Two capsules in one read must both come out, in order.
    #[test]
    fn two_capsules_in_one_read_come_out_in_order() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_datagram(b"first"));
        buf.extend_from_slice(&encode_datagram(b"second"));
        assert_eq!(&taken(&mut buf).unwrap().unwrap()[..], b"first");
        assert_eq!(&taken(&mut buf).unwrap().unwrap()[..], b"second");
        assert!(taken(&mut buf).is_none());
    }

    /// A length is a number the other end writes, and the encoding lets it write one no stream
    /// could ever deliver. Waiting for it is what turns four bytes into memory without a bound, so
    /// it has to be refused on the header rather than on the bytes that never arrive.
    #[test]
    fn a_capsule_longer_than_any_packet_is_refused_rather_than_waited_for() {
        let mut buf = BytesMut::new();
        varint::put(&mut buf, DATAGRAM);
        varint::put(&mut buf, u64::MAX >> 2);

        let refused = take_capsule(&mut buf).expect_err("a length nothing could satisfy");
        assert_eq!(refused.0, u64::MAX >> 2);
        assert_eq!(buf.len(), 9, "and nothing was consumed");
    }

    /// The ceiling is where it says it is, on both sides of it.
    #[test]
    fn the_ceiling_admits_what_it_says_it_admits() {
        let mut just_under = BytesMut::new();
        varint::put(&mut just_under, DATAGRAM);
        varint::put(&mut just_under, MAX_CAPSULE);
        assert!(
            take_capsule(&mut just_under).is_ok(),
            "a capsule at the ceiling is waited for, not refused"
        );

        let mut just_over = BytesMut::new();
        varint::put(&mut just_over, DATAGRAM);
        varint::put(&mut just_over, MAX_CAPSULE + 1);
        assert!(take_capsule(&mut just_over).is_err());
    }
}
