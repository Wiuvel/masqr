//! QPACK (RFC 9204), as much of it as one request and one response need.
//!
//! This side declares a dynamic table of capacity zero, so every field section either direction
//! writes is self-contained: static-table references and literals, nothing that refers to state
//! built up on another stream. That is why there is no encoder or decoder stream here, which
//! RFC 9204 §4.2 permits for a table this size, and why a reference into a dynamic table is a
//! protocol error rather than something to wait for.
//!
//! The request is written with plain literals; the response is read in any form the static-only
//! subset allows, Huffman included.

use bytes::{BufMut, BytesMut};

use super::huffman::{self, HuffmanError};

/// RFC 9204 Appendix A: the static table, indexed from zero.
#[rustfmt::skip]
const STATIC: [(&[u8], &[u8]); 99] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

/// One field line: a name and its value, as bytes — HTTP does not promise either is UTF-8.
pub type Field = (Vec<u8>, Vec<u8>);

/// Why a field section could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QpackError {
    #[error("the field section ends in the middle of a field line")]
    Truncated,
    #[error("the field section refers to a dynamic table, which this side declared no room for")]
    Dynamic,
    #[error("the field section refers to static entry {0}, and the table ends at 98")]
    UnknownIndex(u64),
    #[error("an integer in the field section runs longer than any field needs")]
    Overflow,
    #[error("a Huffman-coded string: {0}")]
    Huffman(#[from] HuffmanError),
}

/// Write a field section: the prefix that says no dynamic table is involved, then each field as
/// the smallest static-only form that fits it.
///
/// A field the static table has whole is one byte. A field whose name it has is a reference and a
/// literal value. Anything else is written out in full. None is Huffman-coded: the saving on one
/// request per connection is a few bytes, and plain literals are the form every decoder must read.
pub fn encode(fields: &[(&[u8], &[u8])], out: &mut BytesMut) {
    // Required Insert Count 0, and a Delta Base of 0 with the sign bit clear.
    out.put_slice(&[0x00, 0x00]);
    for &(name, value) in fields {
        if let Some(index) = STATIC.iter().position(|&entry| entry == (name, value)) {
            // Indexed field line, static: 1 · T=1 · index.
            put_int(out, 6, 0b1100_0000, index as u64);
        } else if let Some(index) = STATIC.iter().position(|&(known, _)| known == name) {
            // Literal with name reference, static, may be indexed by intermediaries:
            // 01 · N=0 · T=1 · index.
            put_int(out, 4, 0b0101_0000, index as u64);
            put_string(out, value);
        } else {
            // Literal with literal name: 001 · N=0 · H=0 · length.
            put_int(out, 3, 0b0010_0000, name.len() as u64);
            out.put_slice(name);
            put_string(out, value);
        }
    }
}

/// Read a field section written without a dynamic table.
pub fn decode(section: &[u8]) -> Result<Vec<Field>, QpackError> {
    let mut rest = section;
    let (required_insert_count, used) = get_int(rest, 8)?;
    rest = &rest[used..];
    if required_insert_count != 0 {
        return Err(QpackError::Dynamic);
    }
    // The Base means nothing without a dynamic table, but it is part of the prefix.
    let (_, used) = get_int(rest, 7)?;
    rest = &rest[used..];

    let mut fields = Vec::new();
    while let Some(&first) = rest.first() {
        if first & 0b1000_0000 != 0 {
            // Indexed field line.
            if first & 0b0100_0000 == 0 {
                return Err(QpackError::Dynamic);
            }
            let (index, used) = get_int(rest, 6)?;
            rest = &rest[used..];
            let (name, value) = static_entry(index)?;
            fields.push((name.to_vec(), value.to_vec()));
        } else if first & 0b0100_0000 != 0 {
            // Literal with name reference.
            if first & 0b0001_0000 == 0 {
                return Err(QpackError::Dynamic);
            }
            let (index, used) = get_int(rest, 4)?;
            rest = &rest[used..];
            let (name, _) = static_entry(index)?;
            let (value, used) = get_string(rest, 7)?;
            rest = &rest[used..];
            fields.push((name.to_vec(), value));
        } else if first & 0b0010_0000 != 0 {
            // Literal with literal name; its Huffman bit sits below the N bit.
            let (name, used) = get_string(rest, 3)?;
            rest = &rest[used..];
            let (value, used) = get_string(rest, 7)?;
            rest = &rest[used..];
            fields.push((name, value));
        } else {
            // 0001 and 0000: the two post-Base forms, which only ever point into a dynamic table.
            return Err(QpackError::Dynamic);
        }
    }
    Ok(fields)
}

fn static_entry(index: u64) -> Result<(&'static [u8], &'static [u8]), QpackError> {
    usize::try_from(index)
        .ok()
        .and_then(|index| STATIC.get(index).copied())
        .ok_or(QpackError::UnknownIndex(index))
}

/// An RFC 7541 §5.1 prefixed integer: the low `prefix` bits of the first byte, continued in
/// seven-bit groups when they are all ones. `flags` fills the bits above the prefix.
fn put_int(out: &mut BytesMut, prefix: u32, flags: u8, value: u64) {
    let max = (1u64 << prefix) - 1;
    if value < max {
        out.put_u8(flags | value as u8);
        return;
    }
    out.put_u8(flags | max as u8);
    let mut rest = value - max;
    while rest >= 0x80 {
        out.put_u8(0x80 | (rest & 0x7f) as u8);
        rest >>= 7;
    }
    out.put_u8(rest as u8);
}

/// Read a prefixed integer; returns it and how many bytes it took.
fn get_int(buf: &[u8], prefix: u32) -> Result<(u64, usize), QpackError> {
    let max = (1u64 << prefix) - 1;
    let first = *buf.first().ok_or(QpackError::Truncated)?;
    let mut value = u64::from(first) & max;
    if value < max {
        return Ok((value, 1));
    }
    let mut shift = 0u32;
    for (position, &byte) in buf.iter().enumerate().skip(1) {
        // Nine continuation bytes already carry 63 bits; a tenth is a number no field needs.
        if shift > 56 {
            return Err(QpackError::Overflow);
        }
        value += u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, position + 1));
        }
    }
    Err(QpackError::Truncated)
}

/// A plain string literal: H=0 and a seven-bit length, then the bytes.
fn put_string(out: &mut BytesMut, value: &[u8]) {
    put_int(out, 7, 0, value.len() as u64);
    out.put_slice(value);
}

/// Read a string literal whose length has a `prefix`-bit prefix; the Huffman flag is the bit just
/// above it. Returns the decoded bytes and how many bytes of `buf` it took.
fn get_string(buf: &[u8], prefix: u32) -> Result<(Vec<u8>, usize), QpackError> {
    let first = *buf.first().ok_or(QpackError::Truncated)?;
    let huffman = first & (1 << prefix) != 0;
    let (length, used) = get_int(buf, prefix)?;
    let end = usize::try_from(length)
        .ok()
        .and_then(|length| used.checked_add(length))
        .filter(|&end| end <= buf.len())
        .ok_or(QpackError::Truncated)?;
    let raw = &buf[used..end];
    let value = if huffman {
        huffman::decode(raw)?
    } else {
        raw.to_vec()
    };
    Ok((value, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, value: &str) -> Field {
        (name.as_bytes().to_vec(), value.as_bytes().to_vec())
    }

    /// The entries this core's own request and the response it waits for depend on, at the indices
    /// RFC 9204 Appendix A gives them.
    #[test]
    fn the_static_table_is_where_the_rfc_puts_it() {
        assert_eq!(STATIC[0], (&b":authority"[..], &b""[..]));
        assert_eq!(STATIC[1], (&b":path"[..], &b"/"[..]));
        assert_eq!(STATIC[15], (&b":method"[..], &b"CONNECT"[..]));
        assert_eq!(STATIC[23], (&b":scheme"[..], &b"https"[..]));
        assert_eq!(STATIC[25], (&b":status"[..], &b"200"[..]));
        assert_eq!(STATIC[71], (&b":status"[..], &b"500"[..]));
        assert_eq!(STATIC[95], (&b"user-agent"[..], &b""[..]));
        assert_eq!(STATIC[98], (&b"x-frame-options"[..], &b"sameorigin"[..]));
    }

    /// The request this core sends, byte for byte, and back through the decoder unchanged.
    #[test]
    fn the_connect_request_round_trips() {
        let request: [(&[u8], &[u8]); 7] = [
            (b":method", b"CONNECT"),
            (b":protocol", b"cf-connect-ip"),
            (b":scheme", b"https"),
            (b":authority", b"cloudflareaccess.com"),
            (b":path", b"/"),
            (b"capsule-protocol", b"?1"),
            (b"user-agent", b""),
        ];
        let mut out = BytesMut::new();
        encode(&request, &mut out);

        let mut expected = vec![0x00, 0x00, 0xc0 | 15];
        expected.extend_from_slice(b"\x27\x02:protocol\x0dcf-connect-ip");
        expected.push(0xc0 | 23);
        expected.extend_from_slice(b"\x50\x14cloudflareaccess.com");
        expected.push(0xc0 | 1);
        expected.extend_from_slice(b"\x27\x09capsule-protocol\x02?1");
        expected.push(0xff);
        expected.push(95 - 63);
        assert_eq!(&out[..], &expected[..]);

        let decoded = decode(&out).expect("its own output reads");
        let wanted: Vec<Field> = request
            .iter()
            .map(|&(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(decoded, wanted);
    }

    /// A 200 the way a server usually writes it: one indexed byte.
    #[test]
    fn an_indexed_status_reads() {
        assert_eq!(
            decode(&[0x00, 0x00, 0xd9]),
            Ok(vec![field(":status", "200")])
        );
    }

    /// A status the table has no entry for arrives as a reference to the name and a literal value,
    /// either plain or Huffman-coded; a header the table does not know at all arrives whole.
    #[test]
    fn literal_forms_read_plain_and_huffman_coded() {
        // :status 403 as name reference 24 and a plain value.
        assert_eq!(
            decode(b"\x00\x00\x5f\x09\x03403"),
            Ok(vec![field(":status", "403")])
        );
        // The same with the value Huffman-coded: '4' 011010, '0' 00000, '3' 011001, then ones.
        assert_eq!(
            decode(b"\x00\x00\x5f\x09\x83\x68\x0c\xff"),
            Ok(vec![field(":status", "403")])
        );
        // A name the table does not have, both name and value Huffman-coded (RFC 7541 C.4.3): an
        // eight-byte name overflows the three-bit prefix, hence 0x2f 0x01.
        let mut custom = vec![0x00, 0x00, 0x2f, 0x01];
        custom.extend_from_slice(b"\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f");
        custom.push(0x89);
        custom.extend_from_slice(b"\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf");
        assert_eq!(
            decode(&custom),
            Ok(vec![field("custom-key", "custom-value")])
        );
    }

    /// Anything that points into a dynamic table is refused: this side declared none, so the
    /// endpoint writing one is a protocol error, not a reason to wait.
    #[test]
    fn every_dynamic_reference_is_refused() {
        for section in [
            &[0x01, 0x00][..],             // a Required Insert Count
            &[0x00, 0x00, 0x80][..],       // indexed, T=0
            &[0x00, 0x00, 0x40, 0x00][..], // name reference, T=0
            &[0x00, 0x00, 0x10][..],       // indexed, post-Base
            &[0x00, 0x00, 0x00, 0x00][..], // name reference, post-Base
        ] {
            assert_eq!(decode(section), Err(QpackError::Dynamic), "{section:02x?}");
        }
    }

    #[test]
    fn a_section_cut_short_or_out_of_range_is_refused() {
        assert_eq!(decode(&[]), Err(QpackError::Truncated));
        assert_eq!(decode(&[0x00]), Err(QpackError::Truncated));
        // A literal value that claims more bytes than follow.
        assert_eq!(
            decode(b"\x00\x00\x5f\x09\x05403"),
            Err(QpackError::Truncated)
        );
        // Index 99, one past the end of the table.
        assert_eq!(
            decode(&[0x00, 0x00, 0xff, 99 - 63]),
            Err(QpackError::UnknownIndex(99))
        );
        // A continuation that never stops.
        assert_eq!(
            decode(&[
                0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
            ]),
            Err(QpackError::Overflow)
        );
    }

    /// The prefixed integers of RFC 7541 C.1, which QPACK reuses unchanged.
    #[test]
    fn prefixed_integers_match_the_rfc_examples() {
        let mut out = BytesMut::new();
        put_int(&mut out, 5, 0, 10);
        assert_eq!(&out[..], &[0x0a]);
        assert_eq!(get_int(&out, 5), Ok((10, 1)));

        let mut out = BytesMut::new();
        put_int(&mut out, 5, 0, 1337);
        assert_eq!(&out[..], &[0x1f, 0x9a, 0x0a]);
        assert_eq!(get_int(&out, 5), Ok((1337, 3)));

        let mut out = BytesMut::new();
        put_int(&mut out, 8, 0, 42);
        assert_eq!(&out[..], &[0x2a]);
    }
}
