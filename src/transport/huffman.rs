//! The Huffman code HPACK and QPACK compress header strings with (RFC 7541 Appendix B).
//!
//! Only the decoding side. The endpoint may Huffman-code any string in its response; this core's own
//! request is written as plain literals, which the format always permits.

/// Each symbol's code and its length in bits, indexed by symbol. 256 is EOS, which only ever
/// appears as padding.
///
/// The code is canonical: codes of one length are consecutive in symbol order, and each length
/// starts where the last one ended, shifted. The decoder below needs nothing from this table but
/// the lengths for that reason, and a test holds the table to it.
#[rustfmt::skip]
const CODES: [(u32, u8); 257] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
    (0x3fffffff, 30),
];

const EOS: u16 = 256;
const LONGEST: usize = 30;

/// How many symbols have a code of each length.
const COUNT: [u16; LONGEST + 1] = {
    let mut count = [0u16; LONGEST + 1];
    let mut symbol = 0;
    while symbol < CODES.len() {
        count[CODES[symbol].1 as usize] += 1;
        symbol += 1;
    }
    count
};

/// The symbols ordered by code length and, within one length, by symbol: the order the codes are
/// handed out in.
const SYMBOLS: [u16; 257] = {
    let mut next = [0u16; LONGEST + 1];
    let mut length = 1;
    while length <= LONGEST {
        next[length] = next[length - 1] + COUNT[length - 1];
        length += 1;
    }
    let mut symbols = [0u16; 257];
    let mut symbol = 0;
    while symbol < CODES.len() {
        let length = CODES[symbol].1 as usize;
        symbols[next[length] as usize] = symbol as u16;
        next[length] += 1;
        symbol += 1;
    }
    symbols
};

/// Why a Huffman-coded string could not be read. Each is the peer writing something the format
/// forbids (RFC 7541 §5.2), so the header block is refused rather than guessed at.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HuffmanError {
    #[error("the string codes the end-of-string symbol")]
    Eos,
    #[error("the string ends in padding longer than seven bits or not made of ones")]
    Padding,
}

/// Decode a Huffman-coded string.
///
/// Read a bit at a time against the canonical ranges: at each length, the codes of that length are
/// the `COUNT[length]` values starting at `first`, so a code is complete as soon as it falls inside
/// its length's range. Speed does not matter here — one response per connection.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, HuffmanError> {
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let mut code = 0u32;
    let mut first = 0u32;
    let mut index = 0usize;
    let mut length = 0usize;
    let mut all_ones = true;

    for byte in input {
        for shift in (0..8).rev() {
            let bit = u32::from((byte >> shift) & 1);
            code |= bit;
            all_ones &= bit == 1;
            length += 1;

            let count = u32::from(COUNT[length]);
            if code - first < count {
                let symbol = SYMBOLS[index + (code - first) as usize];
                if symbol == EOS {
                    return Err(HuffmanError::Eos);
                }
                out.push(symbol as u8);
                (code, first, index, length, all_ones) = (0, 0, 0, 0, true);
                continue;
            }
            // No bound check on `length`: the code is complete, so thirty bits always end in a
            // symbol, and the longest code of all is EOS.
            index += count as usize;
            first = (first + count) << 1;
            code <<= 1;
        }
    }

    // What is left is padding: the high bits of EOS, which are all ones, and fewer than a byte.
    if length > 7 || !all_ones {
        return Err(HuffmanError::Padding);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoder, kept to the tests: it is how the round-trip below reaches every symbol.
    fn encode(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pending = 0u64;
        let mut bits = 0u32;
        for &byte in input {
            let (code, length) = CODES[byte as usize];
            pending = (pending << length) | u64::from(code);
            bits += u32::from(length);
            while bits >= 8 {
                bits -= 8;
                out.push((pending >> bits) as u8);
            }
        }
        if bits > 0 {
            out.push(((pending << (8 - bits)) | (0xff >> bits)) as u8);
        }
        out
    }

    /// The decoder takes only the lengths from the table and derives the codes; this is the proof
    /// that deriving them gives back every code RFC 7541 lists.
    #[test]
    fn the_table_is_canonical() {
        let mut order: Vec<usize> = (0..CODES.len()).collect();
        order.sort_by_key(|&symbol| (CODES[symbol].1, symbol));
        let mut expected = 0u32;
        let mut previous = CODES[order[0]].1;
        for (position, &symbol) in order.iter().enumerate() {
            let (code, length) = CODES[symbol];
            if position > 0 {
                expected = (expected + 1) << (length - previous);
            }
            previous = length;
            assert_eq!(code, expected, "symbol {symbol}");
        }
    }

    /// Kraft's sum is exactly one: every bit sequence is the start of some code, which is why the
    /// decoder never runs past the longest length.
    #[test]
    fn the_code_is_complete() {
        let sum: u64 = CODES
            .iter()
            .map(|&(_, length)| 1u64 << (LONGEST - length as usize))
            .sum();
        assert_eq!(sum, 1 << LONGEST);
    }

    /// RFC 7541 Appendix C.4, the request examples with Huffman coding.
    #[test]
    fn the_rfc_examples_decode() {
        for (coded, plain) in [
            (
                &b"\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"[..],
                &b"www.example.com"[..],
            ),
            (&b"\xa8\xeb\x10\x64\x9c\xbf"[..], &b"no-cache"[..]),
            (&b"\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f"[..], &b"custom-key"[..]),
            (
                &b"\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf"[..],
                &b"custom-value"[..],
            ),
        ] {
            assert_eq!(decode(coded).as_deref(), Ok(plain));
            assert_eq!(encode(plain), coded);
        }
    }

    #[test]
    fn every_byte_value_survives_the_round_trip() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).as_deref(), Ok(&all[..]));
        assert_eq!(decode(&[]).as_deref(), Ok(&b""[..]));
    }

    /// RFC 7541 §5.2: padding is at most seven bits, all ones, and EOS itself is never coded.
    #[test]
    fn padding_and_eos_are_held_to_the_rules() {
        // '0' is 00000 (five bits); three bits of ones pad the byte.
        assert_eq!(decode(&[0b0000_0111]).as_deref(), Ok(&b"0"[..]));
        // The same symbol padded with something other than ones.
        assert_eq!(decode(&[0b0000_0101]), Err(HuffmanError::Padding));
        // A whole byte of ones is eight bits of padding: one too many.
        assert_eq!(decode(&[0b0000_0111, 0xff]), Err(HuffmanError::Padding));
        // EOS written out in full: thirty ones.
        assert_eq!(decode(&[0xff, 0xff, 0xff, 0xfc]), Err(HuffmanError::Eos));
    }
}
