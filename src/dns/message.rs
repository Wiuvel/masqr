//! Reading DNS messages. Reading only.
//!
//! This core forwards queries and returns the answer it was given, byte for byte. It never speaks
//! for a name itself, so it needs to understand a message well enough to act on it and no better.
//! Half a serialiser is how a forwarder starts rewriting what it passes on.
//!
//! Everything is bounds-checked and every loop is bounded: a message arrives from the network
//! before anything has been decided about it, so a malformed one must be an error and never a
//! panic. Compression pointers and label lengths are the two shapes that make that hard.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Resource record types this core acts on. Anything else is passed through without inspection.
pub const TYPE_A: u16 = 1;
/// The record type carrying an IPv6 address.
pub const TYPE_AAAA: u16 = 28;

/// The internet class. A query in any other class is not something this core has an opinion about.
pub const CLASS_IN: u16 = 1;

/// Bytes before the first question: id, flags, and the four section counts.
const HEADER_LEN: usize = 12;

/// The two high bits of a length byte mark a compression pointer rather than a label.
const POINTER_MASK: u8 = 0xc0;

/// A single label may be 63 bytes, and a whole name 255. Both are the protocol's limits, and both
/// are what stops a crafted message from making a reader allocate without bound.
const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 255;

/// How many compression jumps one name may take.
///
/// A pointer may only ever point backwards, so a well-formed name cannot need many. The cap is what
/// makes a cycle — a pointer to itself, or two pointing at each other — terminate as an error
/// instead of spinning.
const MAX_JUMPS: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
/// Why a message could not be read.
///
/// Every one of these is a message that arrived, not a failure to receive one: reading stops at
/// the first thing that does not make sense rather than guessing past it.
pub enum MessageError {
    #[error("the message ends before its {0} does")]
    Truncated(&'static str),
    #[error("the message carries no question")]
    NoQuestion,
    #[error("a label is {0} bytes, and 63 is the most a label may be")]
    LabelTooLong(usize),
    #[error("a name is longer than the 255 bytes a name may be")]
    NameTooLong,
    #[error("a compression pointer leads outside the message")]
    PointerOutOfRange,
    #[error("a compression pointer leads back on itself")]
    PointerLoop,
}

/// What a query is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The transaction id, so a reply can be matched to it.
    pub id: u16,
    /// The name asked about, lowercase, without a trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// One address a reply carries, and how long it may be believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The name this record is about, which after a CNAME chain is not the name that was asked.
    pub name: String,
    pub address: IpAddr,
    pub ttl: u32,
}

/// Read the question out of a query.
///
/// Only the first question is read. A message may declare several, but no resolver in practice
/// sends one, and acting on a message whose questions disagree about policy would mean choosing
/// which of them to obey.
pub fn read_query(message: &[u8]) -> Result<Query, MessageError> {
    let header = read_header(message)?;
    if header.questions == 0 {
        return Err(MessageError::NoQuestion);
    }

    let (name, after) = read_name(message, HEADER_LEN)?;
    let qtype = read_u16(message, after).ok_or(MessageError::Truncated("question type"))?;
    let qclass = read_u16(message, after + 2).ok_or(MessageError::Truncated("question class"))?;
    Ok(Query {
        id: header.id,
        name,
        qtype,
        qclass,
    })
}

/// Read the addresses a reply carries, in the order it carries them.
///
/// Only the answer section, and only `A` and `AAAA` within it. The authority and additional
/// sections may name addresses too, but those are not answers to the question that was asked, and
/// routing an address nobody was told to use is how a tunnel acquires traffic nobody asked it to
/// carry.
///
/// A record this reader does not understand is skipped by its declared length rather than refused:
/// an unknown type is ordinary, and a reply that mixes one in is still a good reply.
pub fn read_answers(message: &[u8]) -> Result<Vec<Record>, MessageError> {
    let header = read_header(message)?;
    let mut at = HEADER_LEN;

    for _ in 0..header.questions {
        let (_, after) = read_name(message, at)?;
        // Type and class follow the name in a question, and neither is needed here.
        at = after + 4;
    }

    let mut found = Vec::new();
    for _ in 0..header.answers {
        let (name, after) = read_name(message, at)?;
        let rtype = read_u16(message, after).ok_or(MessageError::Truncated("record type"))?;
        let rclass = read_u16(message, after + 2).ok_or(MessageError::Truncated("record class"))?;
        let ttl = read_u32(message, after + 4).ok_or(MessageError::Truncated("record ttl"))?;
        let length =
            usize::from(read_u16(message, after + 8).ok_or(MessageError::Truncated("record"))?);

        let data = after + 10;
        let end = data
            .checked_add(length)
            .filter(|end| *end <= message.len())
            .ok_or(MessageError::Truncated("record data"))?;

        if rclass == CLASS_IN {
            match (rtype, length) {
                (TYPE_A, 4) => {
                    let octets: [u8; 4] = message[data..end].try_into().expect("four bytes");
                    found.push(Record {
                        name,
                        address: IpAddr::V4(Ipv4Addr::from(octets)),
                        ttl,
                    });
                }
                (TYPE_AAAA, 16) => {
                    let octets: [u8; 16] = message[data..end].try_into().expect("sixteen bytes");
                    found.push(Record {
                        name,
                        address: IpAddr::V6(Ipv6Addr::from(octets)),
                        ttl,
                    });
                }
                // Any other type, and an A or AAAA whose length disagrees with its type: skipped.
                // The second is malformed, but skipping it costs one address and refusing the
                // message costs the whole answer.
                _ => {}
            }
        }
        at = end;
    }
    Ok(found)
}

/// Read a name, following compression pointers, and say where the name ended in the stream.
///
/// The returned offset is the position after the name *as it was written here* — after the two
/// bytes of the first pointer, if one was taken. That is what a caller walking the message needs;
/// where the pointer led is nobody's business but this function's.
pub fn read_name(message: &[u8], start: usize) -> Result<(String, usize), MessageError> {
    let mut name = String::new();
    let mut at = start;
    let mut after = None;
    let mut jumps = 0;
    let mut seen = 0;

    loop {
        let length = *message.get(at).ok_or(MessageError::Truncated("name"))?;

        if length & POINTER_MASK == POINTER_MASK {
            let target = read_u16(message, at).ok_or(MessageError::Truncated("name pointer"))?;
            let target = usize::from(target & 0x3fff);
            if target >= message.len() {
                return Err(MessageError::PointerOutOfRange);
            }
            // A pointer must lead backwards; anything else is either a cycle or a message written
            // to make this loop.
            if target >= at {
                return Err(MessageError::PointerLoop);
            }
            jumps += 1;
            if jumps > MAX_JUMPS {
                return Err(MessageError::PointerLoop);
            }
            // Only the first jump decides where the name ended for the caller.
            after.get_or_insert(at + 2);
            at = target;
            continue;
        }

        if length == 0 {
            return Ok((name, after.unwrap_or(at + 1)));
        }

        let length = usize::from(length);
        if length > MAX_LABEL {
            return Err(MessageError::LabelTooLong(length));
        }
        seen += length + 1;
        if seen > MAX_NAME {
            return Err(MessageError::NameTooLong);
        }

        let from = at + 1;
        let to = from
            .checked_add(length)
            .filter(|to| *to <= message.len())
            .ok_or(MessageError::Truncated("label"))?;

        if !name.is_empty() {
            name.push('.');
        }
        // Names are compared case-insensitively, and every comparison this core makes is against a
        // policy written in lowercase. Lowering here means no caller has to remember to.
        for byte in &message[from..to] {
            name.push(byte.to_ascii_lowercase() as char);
        }
        at = to;
    }
}

struct Header {
    id: u16,
    questions: u16,
    answers: u16,
}

fn read_header(message: &[u8]) -> Result<Header, MessageError> {
    if message.len() < HEADER_LEN {
        return Err(MessageError::Truncated("header"));
    }
    Ok(Header {
        id: u16::from_be_bytes([message[0], message[1]]),
        questions: u16::from_be_bytes([message[4], message[5]]),
        answers: u16::from_be_bytes([message[6], message[7]]),
    })
}

fn read_u16(message: &[u8], at: usize) -> Option<u16> {
    let pair = message.get(at..at + 2)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

fn read_u32(message: &[u8], at: usize) -> Option<u32> {
    let quad = message.get(at..at + 4)?;
    Some(u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Building messages belongs to the tests and only to the tests: the core forwards what it is
    /// given, so a builder in the library would be a serialiser nothing calls and everything could
    /// start calling.
    #[derive(Default)]
    struct Builder {
        bytes: Vec<u8>,
    }

    impl Builder {
        fn header(id: u16, questions: u16, answers: u16) -> Self {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&id.to_be_bytes());
            bytes.extend_from_slice(&0x8180u16.to_be_bytes()); // a standard reply, no error
            bytes.extend_from_slice(&questions.to_be_bytes());
            bytes.extend_from_slice(&answers.to_be_bytes());
            bytes.extend_from_slice(&0u16.to_be_bytes()); // authority
            bytes.extend_from_slice(&0u16.to_be_bytes()); // additional
            Self { bytes }
        }

        fn name(mut self, name: &str) -> Self {
            for label in name.split('.') {
                self.bytes.push(label.len() as u8);
                self.bytes.extend_from_slice(label.as_bytes());
            }
            self.bytes.push(0);
            self
        }

        /// A name written as a pointer to an earlier one.
        fn pointer(mut self, to: u16) -> Self {
            self.bytes.extend_from_slice(&(0xc000 | to).to_be_bytes());
            self
        }

        fn u16(mut self, value: u16) -> Self {
            self.bytes.extend_from_slice(&value.to_be_bytes());
            self
        }

        fn record(mut self, rtype: u16, ttl: u32, data: &[u8]) -> Self {
            self.bytes.extend_from_slice(&rtype.to_be_bytes());
            self.bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
            self.bytes.extend_from_slice(&ttl.to_be_bytes());
            self.bytes
                .extend_from_slice(&(data.len() as u16).to_be_bytes());
            self.bytes.extend_from_slice(data);
            self
        }

        fn raw(mut self, bytes: &[u8]) -> Self {
            self.bytes.extend_from_slice(bytes);
            self
        }

        fn done(self) -> Vec<u8> {
            self.bytes
        }
    }

    #[test]
    fn a_query_says_what_it_asks_about() {
        let message = Builder::header(0x2a2a, 1, 0)
            .name("Www.Example.COM")
            .u16(TYPE_A)
            .u16(CLASS_IN)
            .done();

        let query = read_query(&message).unwrap();
        assert_eq!(query.id, 0x2a2a);
        // Lowered here so that no policy comparison anywhere else has to remember to.
        assert_eq!(query.name, "www.example.com");
        assert_eq!(query.qtype, TYPE_A);
        assert_eq!(query.qclass, CLASS_IN);
    }

    /// The shape a real reply has: the answer is about the name at the end of a CNAME chain, not
    /// about the name that was asked. Both addresses have to be found, and the routing that follows
    /// is about the addresses, not about which name produced them.
    #[test]
    fn a_reply_gives_up_its_addresses_through_a_cname() {
        let message = Builder::header(1, 1, 3)
            .name("cdn.example.com")
            .u16(TYPE_A)
            .u16(CLASS_IN)
            // answer 1: the CNAME, whose owner is the question name written as a pointer
            .pointer(HEADER_LEN as u16)
            .record(5, 300, &[3, b'e', b'd', b'g', b'e', 0])
            // answer 2 and 3: the addresses, owned by the target
            .name("edge")
            .record(TYPE_A, 60, &[104, 16, 0, 1])
            .name("edge")
            .record(
                TYPE_AAAA,
                60,
                &[0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            )
            .done();

        let answers = read_answers(&message).unwrap();
        assert_eq!(answers.len(), 2, "the CNAME is not an address");
        assert_eq!(answers[0].address, "104.16.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(answers[0].ttl, 60);
        assert_eq!(answers[0].name, "edge");
        assert_eq!(
            answers[1].address,
            "2606:4700::1".parse::<IpAddr>().unwrap()
        );
    }

    /// An unknown record type is ordinary. Skipping it by its declared length keeps the rest of the
    /// answer readable; refusing the message would throw away addresses that are perfectly good.
    #[test]
    fn an_unknown_record_is_stepped_over_rather_than_refused() {
        let message = Builder::header(1, 1, 2)
            .name("example.com")
            .u16(TYPE_A)
            .u16(CLASS_IN)
            .name("example.com")
            .record(99, 300, &[1, 2, 3, 4, 5, 6, 7])
            .name("example.com")
            .record(TYPE_A, 30, &[1, 1, 1, 1])
            .done();

        let answers = read_answers(&message).unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].address, "1.1.1.1".parse::<IpAddr>().unwrap());
    }

    /// A record whose length disagrees with its type is malformed. It costs one address to skip and
    /// the whole answer to refuse, so it is skipped.
    #[test]
    fn an_address_record_of_the_wrong_size_is_skipped() {
        let message = Builder::header(1, 1, 1)
            .name("example.com")
            .u16(TYPE_A)
            .u16(CLASS_IN)
            .name("example.com")
            .record(TYPE_A, 30, &[1, 1, 1])
            .done();
        assert_eq!(read_answers(&message).unwrap(), vec![]);
    }

    /// A record in another class is not about the internet, whatever its type says.
    #[test]
    fn a_record_outside_the_internet_class_is_not_an_address() {
        let mut message = Builder::header(1, 1, 1)
            .name("example.com")
            .u16(TYPE_A)
            .u16(CLASS_IN)
            .name("example.com")
            .record(TYPE_A, 30, &[1, 1, 1, 1])
            .done();
        // The class sits two bytes after the type, at the end of the record header.
        let class_at = message.len() - 4 - 4 - 2 - 2;
        message[class_at..class_at + 2].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(read_answers(&message).unwrap(), vec![]);
    }

    /// A pointer that leads forward, or at itself, is the shape that makes a naive reader spin.
    #[test]
    fn a_pointer_that_does_not_lead_backwards_is_refused() {
        let message = Builder::header(1, 1, 0).pointer(HEADER_LEN as u16).done();
        assert_eq!(
            read_name(&message, HEADER_LEN),
            Err(MessageError::PointerLoop)
        );
    }

    #[test]
    fn a_pointer_past_the_end_is_refused() {
        let message = Builder::header(1, 1, 0).pointer(9000).done();
        assert_eq!(
            read_name(&message, HEADER_LEN),
            Err(MessageError::PointerOutOfRange)
        );
    }

    /// A name written as a pointer ends, for the caller walking the message, two bytes on — not
    /// wherever the pointer led. Getting this wrong walks the reader into the middle of a record.
    #[test]
    fn a_compressed_name_ends_where_it_was_written() {
        let message = Builder::header(1, 1, 0)
            .name("example.com")
            .u16(TYPE_A)
            .u16(CLASS_IN)
            .pointer(HEADER_LEN as u16)
            .raw(&[0xaa, 0xbb])
            .done();

        let written_at = message.len() - 4;
        let (name, after) = read_name(&message, written_at).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(after, written_at + 2);
    }

    #[test]
    fn a_label_longer_than_the_protocol_allows_is_refused() {
        let mut message = Builder::header(1, 1, 0).done();
        message.push(64);
        message.extend_from_slice(&[b'a'; 64]);
        message.push(0);
        assert_eq!(
            read_name(&message, HEADER_LEN),
            Err(MessageError::LabelTooLong(64))
        );
    }

    /// Every prefix of a real message is a malformed message, and none of them may panic.
    #[test]
    fn no_truncation_of_a_real_message_panics() {
        let message = Builder::header(7, 1, 1)
            .name("www.example.com")
            .u16(TYPE_A)
            .u16(CLASS_IN)
            .name("www.example.com")
            .record(TYPE_A, 60, &[93, 184, 216, 34])
            .done();

        for cut in 0..message.len() {
            let _ = read_query(&message[..cut]);
            let _ = read_answers(&message[..cut]);
        }
        assert_eq!(read_answers(&message).unwrap().len(), 1);
    }

    #[test]
    fn a_message_with_no_question_is_not_a_query() {
        let message = Builder::header(1, 0, 0).done();
        assert_eq!(read_query(&message), Err(MessageError::NoQuestion));
    }
}
