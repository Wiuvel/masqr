//! HTTP/3 (RFC 9114), as much of it as one extended CONNECT and the datagrams behind it need.
//!
//! Nothing here touches the network. What goes on which QUIC stream, and what the endpoint's
//! streams mean, is decided in `quic.rs`; this is the byte layout of each and the rules about what
//! may arrive where.
//!
//! Three kinds of stream are in play. The control streams, one per side, carry SETTINGS first and
//! stay open for the life of the connection. The request stream carries the CONNECT and its
//! response, then stays open as the tunnel's anchor: nothing is written on it after the request.
//! The packets themselves are QUIC datagrams, each tagged with the request stream it belongs to.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::qpack::{self, QpackError};
use super::varint;

/// Frame types (RFC 9114 §7.2).
pub mod frame {
    pub const DATA: u64 = 0x00;
    pub const HEADERS: u64 = 0x01;
    pub const CANCEL_PUSH: u64 = 0x03;
    pub const SETTINGS: u64 = 0x04;
    pub const PUSH_PROMISE: u64 = 0x05;
    pub const GOAWAY: u64 = 0x07;
    pub const MAX_PUSH_ID: u64 = 0x0d;

    /// Types HTTP/2 used that HTTP/3 reserves: receiving one is an error on any stream.
    pub const FROM_HTTP2: [u64; 4] = [0x02, 0x06, 0x08, 0x09];
}

/// Unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2).
pub mod stream {
    pub const CONTROL: u64 = 0x00;
    pub const PUSH: u64 = 0x01;
    pub const QPACK_ENCODER: u64 = 0x02;
    pub const QPACK_DECODER: u64 = 0x03;
}

/// Setting identifiers.
pub mod setting {
    /// RFC 9220: extended CONNECT, which is what lets a CONNECT carry `:protocol`.
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
    /// RFC 9297: HTTP datagrams.
    pub const H3_DATAGRAM: u64 = 0x33;
    /// The draft-00 identifier for the same thing. Cloudflare's own client still sends it beside
    /// the RFC one, and so does usque, the working third-party client this was checked against.
    pub const H3_DATAGRAM_DRAFT00: u64 = 0x276;

    /// HTTP/2 settings HTTP/3 reserves: receiving one is an error.
    pub const FROM_HTTP2: [u64; 4] = [0x02, 0x03, 0x04, 0x05];
}

/// Error codes a connection is closed with (RFC 9114 §8.1, RFC 9204 §6).
pub mod code {
    pub const NO_ERROR: u64 = 0x100;
    pub const STREAM_CREATION_ERROR: u64 = 0x103;
    pub const CLOSED_CRITICAL_STREAM: u64 = 0x104;
    pub const FRAME_UNEXPECTED: u64 = 0x105;
    pub const FRAME_ERROR: u64 = 0x106;
    pub const EXCESSIVE_LOAD: u64 = 0x107;
    pub const SETTINGS_ERROR: u64 = 0x109;
    pub const MISSING_SETTINGS: u64 = 0x10a;
    pub const MESSAGE_ERROR: u64 = 0x10e;
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
}

/// The largest frame this side will buffer.
///
/// The same reasoning as the capsule ceiling: a length is a number the endpoint writes, and waiting
/// for all of an arbitrary one is memory without a bound. The frames buffered here are SETTINGS,
/// GOAWAY and one response's HEADERS — a few hundred bytes each. Frame types this side does not
/// know are skipped as they arrive rather than buffered, so they are not held to this.
pub const MAX_FRAME: u64 = 65_535;

/// The endpoint breaking a rule of the protocol. Each maps to the code the connection is closed
/// with, so the endpoint's logs say what this side objected to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum H3Error {
    #[error("the endpoint closed its control stream, which lives as long as the connection")]
    ControlClosed,
    #[error("the endpoint opened a second control stream")]
    SecondControl,
    #[error("a frame of type {kind:#x} declared {length} bytes, more than this side buffers")]
    FrameTooLong { kind: u64, length: u64 },
    #[error("a frame of type {kind:#x} arrived on the {stream} stream, where it has no place")]
    Unexpected { kind: u64, stream: &'static str },
    #[error("a {0} frame whose payload does not parse")]
    Malformed(&'static str),
    #[error("the endpoint's control stream began with something other than SETTINGS")]
    MissingSettings,
    #[error("the endpoint's SETTINGS {0}")]
    Settings(&'static str),
    #[error("the response header block: {0}")]
    Qpack(#[from] QpackError),
    #[error("the response {0}")]
    Message(&'static str),
}

impl H3Error {
    /// The application error code to close the connection with.
    pub fn code(&self) -> u64 {
        match self {
            Self::ControlClosed => code::CLOSED_CRITICAL_STREAM,
            Self::SecondControl => code::STREAM_CREATION_ERROR,
            Self::FrameTooLong { .. } => code::EXCESSIVE_LOAD,
            Self::Unexpected { .. } => code::FRAME_UNEXPECTED,
            Self::Malformed(_) => code::FRAME_ERROR,
            Self::MissingSettings => code::MISSING_SETTINGS,
            Self::Settings(_) => code::SETTINGS_ERROR,
            Self::Qpack(_) => code::QPACK_DECOMPRESSION_FAILED,
            Self::Message(_) => code::MESSAGE_ERROR,
        }
    }
}

/// One whole frame.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: u64,
    pub payload: Bytes,
}

/// Turns the bytes of one stream into frames, whatever pieces they arrive in.
///
/// Frame types this side does not know — GREASE, extensions — are dropped here, as RFC 9114 §9
/// requires, and are never seen by the caller. Their bytes are discarded as they arrive, so an
/// unknown frame of any length costs nothing to skip.
#[derive(Debug, Default)]
pub struct FrameReader {
    pending: BytesMut,
    /// Bytes of an unknown frame still to come, which are discarded rather than kept.
    skipping: u64,
}

impl FrameReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add what the stream delivered.
    pub fn extend(&mut self, chunk: &[u8]) {
        self.pending.extend_from_slice(chunk);
    }

    /// The varint at the front, if a whole one has arrived: the type that opens a unidirectional
    /// stream, read before any frame.
    pub fn take_varint(&mut self) -> Option<u64> {
        let (value, used) = varint::get(&self.pending)?;
        self.pending.advance(used);
        Some(value)
    }

    /// The next whole frame of a known type, or `None` until more bytes arrive.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, H3Error> {
        loop {
            if self.skipping > 0 {
                let skip = self
                    .pending
                    .len()
                    .min(usize::try_from(self.skipping).unwrap_or(usize::MAX));
                self.pending.advance(skip);
                self.skipping -= skip as u64;
                if self.skipping > 0 {
                    return Ok(None);
                }
            }
            let Some((kind, type_len)) = varint::get(&self.pending) else {
                return Ok(None);
            };
            let Some((length, length_len)) = varint::get(&self.pending[type_len..]) else {
                return Ok(None);
            };
            if !is_known(kind) {
                self.pending.advance(type_len + length_len);
                self.skipping = length;
                continue;
            }
            if length > MAX_FRAME {
                return Err(H3Error::FrameTooLong { kind, length });
            }
            let total = type_len + length_len + length as usize;
            if self.pending.len() < total {
                return Ok(None);
            }
            self.pending.advance(type_len + length_len);
            let payload = self.pending.split_to(length as usize).freeze();
            return Ok(Some(Frame { kind, payload }));
        }
    }
}

/// Types with a meaning in RFC 9114, including the reserved HTTP/2 ones: those are returned so the
/// stream they arrive on can refuse them.
fn is_known(kind: u64) -> bool {
    matches!(
        kind,
        frame::DATA
            | frame::HEADERS
            | frame::CANCEL_PUSH
            | frame::SETTINGS
            | frame::PUSH_PROMISE
            | frame::GOAWAY
            | frame::MAX_PUSH_ID
    ) || frame::FROM_HTTP2.contains(&kind)
}

fn put_frame(out: &mut BytesMut, kind: u64, payload: &[u8]) {
    out.reserve(varint::len(kind) + varint::len(payload.len() as u64) + payload.len());
    varint::put(out, kind);
    varint::put(out, payload.len() as u64);
    out.put_slice(payload);
}

/// The opening of this side's control stream: its type, then SETTINGS.
///
/// No QPACK setting is sent, which leaves both at their default of zero: no dynamic table, so the
/// endpoint writes only self-contained header blocks and neither side needs QPACK streams.
pub fn control_stream_preface() -> BytesMut {
    let mut settings = BytesMut::new();
    for (id, value) in [
        (setting::ENABLE_CONNECT_PROTOCOL, 1),
        (setting::H3_DATAGRAM, 1),
        (setting::H3_DATAGRAM_DRAFT00, 1),
    ] {
        varint::put(&mut settings, id);
        varint::put(&mut settings, value);
    }
    let mut out = BytesMut::new();
    varint::put(&mut out, stream::CONTROL);
    put_frame(&mut out, frame::SETTINGS, &settings);
    out
}

/// A request's HEADERS frame.
pub fn headers_frame(fields: &[(&[u8], &[u8])]) -> BytesMut {
    let mut section = BytesMut::new();
    qpack::encode(fields, &mut section);
    let mut out = BytesMut::new();
    put_frame(&mut out, frame::HEADERS, &section);
    out
}

/// What the endpoint's SETTINGS say about the two things the tunnel needs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PeerSettings {
    pub h3_datagram: bool,
    pub extended_connect: bool,
}

impl PeerSettings {
    /// Read a SETTINGS payload. Unknown identifiers are ignored; a repeated one, or one HTTP/2 used,
    /// is an error (RFC 9114 §7.2.4).
    pub fn parse(mut payload: &[u8]) -> Result<Self, H3Error> {
        let mut settings = Self::default();
        let mut seen = Vec::new();
        while !payload.is_empty() {
            let (id, id_len) = varint::get(payload).ok_or(H3Error::Malformed("SETTINGS"))?;
            let (value, value_len) =
                varint::get(&payload[id_len..]).ok_or(H3Error::Malformed("SETTINGS"))?;
            payload = &payload[id_len + value_len..];

            if setting::FROM_HTTP2.contains(&id) {
                return Err(H3Error::Settings(
                    "carry an identifier reserved from HTTP/2",
                ));
            }
            if seen.contains(&id) {
                return Err(H3Error::Settings("repeat an identifier"));
            }
            seen.push(id);
            match id {
                setting::H3_DATAGRAM => settings.h3_datagram = value == 1,
                setting::ENABLE_CONNECT_PROTOCOL => settings.extended_connect = value == 1,
                _ => {}
            }
        }
        Ok(settings)
    }
}

/// What the endpoint's control stream has said that the connection has to act on.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlEvent {
    Settings(PeerSettings),
    /// The endpoint is shutting the connection down; the id is the first request it will not
    /// serve.
    GoAway(u64),
}

/// The rules of the endpoint's control stream: SETTINGS first and only once, and no frame that
/// belongs on a request stream.
#[derive(Debug, Default)]
pub struct ControlStream {
    settled: bool,
}

impl ControlStream {
    pub fn on_frame(&mut self, incoming: Frame) -> Result<Option<ControlEvent>, H3Error> {
        if !self.settled {
            if incoming.kind != frame::SETTINGS {
                return Err(H3Error::MissingSettings);
            }
            self.settled = true;
            return PeerSettings::parse(&incoming.payload).map(|s| Some(ControlEvent::Settings(s)));
        }
        match incoming.kind {
            frame::GOAWAY => {
                let (id, used) =
                    varint::get(&incoming.payload).ok_or(H3Error::Malformed("GOAWAY"))?;
                if used != incoming.payload.len() {
                    return Err(H3Error::Malformed("GOAWAY"));
                }
                Ok(Some(ControlEvent::GoAway(id)))
            }
            // Push is never enabled from this side, so these carry nothing to act on.
            frame::CANCEL_PUSH | frame::MAX_PUSH_ID => Ok(None),
            kind => Err(H3Error::Unexpected {
                kind,
                stream: "control",
            }),
        }
    }
}

/// Read the request stream up to the final response, and return its status.
///
/// Interim (1xx) responses are passed over. Anything but HEADERS before the response is an error:
/// a DATA frame would be a body with no response to belong to.
pub fn response_status(incoming: Frame) -> Result<Option<http::StatusCode>, H3Error> {
    if incoming.kind != frame::HEADERS {
        return Err(H3Error::Unexpected {
            kind: incoming.kind,
            stream: "request",
        });
    }
    let fields = qpack::decode(&incoming.payload)?;
    let mut statuses = fields.iter().filter(|(name, _)| name == b":status");
    let status = statuses.next().ok_or(H3Error::Message("has no :status"))?;
    if statuses.next().is_some() {
        return Err(H3Error::Message("has two :status fields"));
    }
    let status = http::StatusCode::from_bytes(&status.1)
        .map_err(|_| H3Error::Message("has a :status that is not a status code"))?;
    Ok((!status.is_informational()).then_some(status))
}

/// Frame one IP packet as the HTTP datagram of the request on `stream_id` (RFC 9297 §2.1), with
/// the context id CONNECT-IP uses for a whole packet (RFC 9484 §6): `varint(id/4) · 0 · packet`.
pub fn datagram(stream_id: u64, packet: &[u8]) -> Bytes {
    let quarter = stream_id / 4;
    let mut out = BytesMut::with_capacity(varint::len(quarter) + 1 + packet.len());
    varint::put(&mut out, quarter);
    out.put_u8(0);
    out.put_slice(packet);
    out.freeze()
}

/// How many bytes `datagram` puts in front of a packet.
pub fn datagram_overhead(stream_id: u64) -> usize {
    varint::len(stream_id / 4) + 1
}

/// The IP packet inside a datagram, or `None` when it belongs to another request or carries a
/// context this tunnel did not ask for. Either is dropped, as RFC 9484 §6 allows.
pub fn datagram_packet(mut datagram: Bytes, stream_id: u64) -> Option<Bytes> {
    let (quarter, used) = varint::get(&datagram)?;
    if quarter != stream_id / 4 {
        return None;
    }
    datagram.advance(used);
    let (context, used) = varint::get(&datagram)?;
    if context != 0 {
        return None;
    }
    datagram.advance(used);
    Some(datagram)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(kind: u64, payload: &[u8]) -> BytesMut {
        let mut out = BytesMut::new();
        put_frame(&mut out, kind, payload);
        out
    }

    /// The preface is the stream type and one SETTINGS frame carrying exactly the three settings
    /// the endpoint was measured to accept.
    #[test]
    fn the_control_preface_says_what_the_tunnel_needs() {
        let preface = control_stream_preface();
        let mut reader = FrameReader::new();
        reader.extend(&preface);
        assert_eq!(reader.take_varint(), Some(stream::CONTROL));
        let settings = reader
            .next_frame()
            .unwrap()
            .expect("a whole SETTINGS frame");
        assert_eq!(settings.kind, frame::SETTINGS);

        let mut ids = Vec::new();
        let mut payload = &settings.payload[..];
        while !payload.is_empty() {
            let (id, a) = varint::get(payload).unwrap();
            let (value, b) = varint::get(&payload[a..]).unwrap();
            ids.push((id, value));
            payload = &payload[a + b..];
        }
        assert_eq!(ids, [(0x08, 1), (0x33, 1), (0x276, 1)]);
        assert_eq!(reader.next_frame(), Ok(None));
    }

    /// Frames arrive in whatever pieces the network chose; none is returned before it is whole.
    #[test]
    fn a_frame_split_across_reads_is_not_returned_early() {
        let whole = encoded(frame::HEADERS, &[0xaa; 300]);
        for cut in [1usize, 2, 3, 100, whole.len() - 1] {
            let mut reader = FrameReader::new();
            reader.extend(&whole[..cut]);
            assert_eq!(reader.next_frame(), Ok(None), "acted on {cut} bytes");
            reader.extend(&whole[cut..]);
            let one = reader.next_frame().unwrap().expect("whole now");
            assert_eq!(one.payload.len(), 300);
        }
    }

    /// A GREASE frame (0x1f·N + 0x21) is skipped, including when it is far larger than anything
    /// this side buffers and arrives a piece at a time, and the frame behind it still comes out.
    #[test]
    fn unknown_frames_are_skipped_without_buffering_them() {
        let grease = 0x1f * 7 + 0x21;
        let big = encoded(grease, &vec![0u8; 200_000]);
        let mut reader = FrameReader::new();
        for piece in big.chunks(1_000) {
            reader.extend(piece);
            assert_eq!(reader.next_frame(), Ok(None));
            assert!(reader.pending.len() <= 1_000, "the unknown frame was kept");
        }
        reader.extend(&encoded(frame::GOAWAY, &[0x04]));
        let goaway = reader.next_frame().unwrap().expect("the frame behind it");
        assert_eq!(goaway.kind, frame::GOAWAY);
    }

    #[test]
    fn a_known_frame_longer_than_the_ceiling_is_refused_on_its_header() {
        let mut header = BytesMut::new();
        varint::put(&mut header, frame::HEADERS);
        varint::put(&mut header, MAX_FRAME + 1);
        let mut reader = FrameReader::new();
        reader.extend(&header);
        assert_eq!(
            reader.next_frame(),
            Err(H3Error::FrameTooLong {
                kind: frame::HEADERS,
                length: MAX_FRAME + 1
            })
        );
    }

    fn settings_payload(pairs: &[(u64, u64)]) -> BytesMut {
        let mut out = BytesMut::new();
        for &(id, value) in pairs {
            varint::put(&mut out, id);
            varint::put(&mut out, value);
        }
        out
    }

    /// The endpoint's SETTINGS as measured: datagrams and extended CONNECT on, among others this
    /// side ignores.
    #[test]
    fn peer_settings_read_what_matters_and_ignore_the_rest() {
        let payload = settings_payload(&[(0x01, 0), (0x33, 1), (0x08, 1), (0x21, 7)]);
        assert_eq!(
            PeerSettings::parse(&payload),
            Ok(PeerSettings {
                h3_datagram: true,
                extended_connect: true
            })
        );
        assert_eq!(
            PeerSettings::parse(&settings_payload(&[(0x06, 16_384)])),
            Ok(PeerSettings::default())
        );
    }

    #[test]
    fn peer_settings_that_break_the_rules_are_refused() {
        let reserved = settings_payload(&[(0x04, 65_535)]);
        assert!(matches!(
            PeerSettings::parse(&reserved),
            Err(H3Error::Settings(_))
        ));
        let repeated = settings_payload(&[(0x33, 1), (0x33, 1)]);
        assert!(matches!(
            PeerSettings::parse(&repeated),
            Err(H3Error::Settings(_))
        ));
        assert_eq!(
            PeerSettings::parse(&[0x33]),
            Err(H3Error::Malformed("SETTINGS"))
        );
    }

    fn whole(kind: u64, payload: &[u8]) -> Frame {
        Frame {
            kind,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn the_control_stream_wants_settings_first_and_once() {
        let mut control = ControlStream::default();
        assert_eq!(
            control.on_frame(whole(frame::GOAWAY, &[0])),
            Err(H3Error::MissingSettings)
        );

        let mut control = ControlStream::default();
        let settings = settings_payload(&[(0x33, 1)]);
        assert!(matches!(
            control.on_frame(whole(frame::SETTINGS, &settings)),
            Ok(Some(ControlEvent::Settings(PeerSettings {
                h3_datagram: true,
                ..
            })))
        ));
        assert_eq!(
            control.on_frame(whole(frame::GOAWAY, &[0x04])),
            Ok(Some(ControlEvent::GoAway(4)))
        );
        assert_eq!(control.on_frame(whole(frame::MAX_PUSH_ID, &[0])), Ok(None));
        for kind in [frame::SETTINGS, frame::HEADERS, frame::DATA, 0x02] {
            assert!(
                matches!(
                    control.on_frame(whole(kind, &[])),
                    Err(H3Error::Unexpected { .. })
                ),
                "{kind:#x}"
            );
        }
        assert_eq!(
            control.on_frame(whole(frame::GOAWAY, &[0x04, 0x00])),
            Err(H3Error::Malformed("GOAWAY"))
        );
    }

    #[test]
    fn the_response_status_is_read_and_interim_ones_passed_over() {
        // 0xd9 is static entry 25, :status 200; 0xff 0x00 is entry 63, :status 100.
        assert_eq!(
            response_status(whole(frame::HEADERS, &[0x00, 0x00, 0xd9])),
            Ok(Some(http::StatusCode::OK))
        );
        assert_eq!(
            response_status(whole(frame::HEADERS, &[0x00, 0x00, 0xff, 0x00])),
            Ok(None)
        );
        // 403 as a name reference and a literal value.
        assert_eq!(
            response_status(whole(frame::HEADERS, b"\x00\x00\x5f\x09\x03403")),
            Ok(Some(http::StatusCode::FORBIDDEN))
        );
    }

    #[test]
    fn a_response_without_a_status_or_before_its_headers_is_refused() {
        assert!(matches!(
            response_status(whole(frame::DATA, b"body")),
            Err(H3Error::Unexpected { .. })
        ));
        // user-agent alone: static entry 95.
        assert_eq!(
            response_status(whole(frame::HEADERS, &[0x00, 0x00, 0xff, 32])),
            Err(H3Error::Message("has no :status"))
        );
        assert_eq!(
            response_status(whole(frame::HEADERS, &[0x00, 0x00, 0xd9, 0xd9])),
            Err(H3Error::Message("has two :status fields"))
        );
        assert!(matches!(
            response_status(whole(frame::HEADERS, &[0x01, 0x00])),
            Err(H3Error::Qpack(QpackError::Dynamic))
        ));
    }

    /// The layout measured against the endpoint: quarter stream id, context 0, the packet.
    #[test]
    fn a_datagram_is_quarter_id_context_zero_and_the_packet() {
        let packet = b"\x45\x00\x00\x1c the rest of it";
        let framed = datagram(0, packet);
        assert_eq!(&framed[..2], &[0x00, 0x00]);
        assert_eq!(&framed[2..], packet);
        assert_eq!(datagram_overhead(0), 2);

        // Stream 256 is quarter 64, which takes a two-byte varint.
        let framed = datagram(256, packet);
        assert_eq!(&framed[..3], &[0x40, 0x40, 0x00]);
        assert_eq!(datagram_overhead(256), 3);
        assert_eq!(datagram_packet(framed, 256).as_deref(), Some(&packet[..]));
    }

    #[test]
    fn a_datagram_for_another_request_or_context_is_dropped() {
        let packet = b"\x45 packet";
        assert_eq!(datagram_packet(datagram(4, packet), 0), None);

        let mut other_context = BytesMut::new();
        varint::put(&mut other_context, 0);
        varint::put(&mut other_context, 2);
        other_context.put_slice(packet);
        assert_eq!(datagram_packet(other_context.freeze(), 0), None);

        assert_eq!(datagram_packet(Bytes::new(), 0), None);
    }
}
