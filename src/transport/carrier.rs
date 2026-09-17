//! Which carrier a tunnel rides: HTTP/3 over QUIC, or HTTP/2 over TCP.
//!
//! HTTP/3 is preferred. Over it each packet is one unreliable QUIC datagram, so a packet lost on
//! the way is lost to the connection inside that sent it, which recovers the way it would on any
//! link — nothing queues behind it. Over HTTP/2 every packet is bytes in a single TCP stream: one
//! lost segment holds up every packet behind it until TCP has resent it, and the delay the queue
//! in front of the tunnel measures includes that stream's own buffer.
//!
//! HTTP/2 stays because a link can drop UDP to the endpoint and still carry TCP to it. Under
//! [`Choice::Auto`] a failed HTTP/3 attempt falls through to HTTP/2 inside the same attempt, and
//! HTTP/3 is then left alone — parked — until something suggests the answer may have changed: the
//! line moved, someone asked for a reconnect, or [`PARK_FOR`] passed. A link that drops QUIC thus
//! costs its timeout once, not on every reconnect.
//!
//! Like the handshake strategy, the choice is process-wide: it belongs to a run, not to one
//! connection.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::Handshake;

/// The transport one tunnel runs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// HTTP/2 over TLS over TCP, packets in capsules on one stream.
    H2,
    /// HTTP/3 over QUIC, each packet one datagram.
    H3,
}

impl Carrier {
    pub fn name(self) -> &'static str {
        match self {
            Carrier::H2 => "h2",
            Carrier::H3 => "h3",
        }
    }
}

/// What a run asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// HTTP/3, falling through to HTTP/2 when it does not open.
    Auto,
    /// HTTP/3 and nothing else: a failure is reported rather than covered.
    H3,
    /// HTTP/2 and nothing else.
    H2,
}

impl Choice {
    pub const ALL: [Choice; 3] = [Choice::Auto, Choice::H3, Choice::H2];

    /// The name this is written as on the command line.
    pub fn name(self) -> &'static str {
        match self {
            Choice::Auto => "auto",
            Choice::H3 => "h3",
            Choice::H2 => "h2",
        }
    }

    pub fn parse(written: &str) -> Option<Choice> {
        Choice::ALL.into_iter().find(|c| c.name() == written)
    }

    const fn code(self) -> u8 {
        match self {
            Choice::Auto => 0,
            Choice::H3 => 1,
            Choice::H2 => 2,
        }
    }

    fn from_code(code: u8) -> Choice {
        match code {
            1 => Choice::H3,
            2 => Choice::H2,
            _ => Choice::Auto,
        }
    }
}

static CHOICE: AtomicU8 = AtomicU8::new(Choice::Auto.code());

/// Choose the carrier every later connection uses.
pub fn select(choice: Choice) {
    CHOICE.store(choice.code(), Ordering::Relaxed);
}

/// The carrier choice in force.
pub fn selected() -> Choice {
    Choice::from_code(CHOICE.load(Ordering::Relaxed))
}

/// The largest packet the adapter hands the tunnel — its MTU. 1280 until the run says otherwise.
///
/// HTTP/3 has to fit each packet into one QUIC datagram, so an HTTP/3 tunnel is only opened once the
/// path can carry a packet this size. HTTP/2 does not care: a stream carries any length.
static LARGEST_PACKET: AtomicUsize = AtomicUsize::new(1280);

pub fn set_largest_packet(bytes: usize) {
    LARGEST_PACKET.store(bytes, Ordering::Relaxed);
}

pub fn largest_packet() -> usize {
    LARGEST_PACKET.load(Ordering::Relaxed)
}

/// How long HTTP/3 is left alone after it failed, when nothing else brings it back sooner.
///
/// Long enough that a link which drops QUIC does not pay the HTTP/3 timeout on every reconnect;
/// short enough that one bad moment does not keep a working link on HTTP/2 for the rest of the day.
pub const PARK_FOR: Duration = Duration::from_secs(600);

/// When HTTP/3 may be tried again, if it is parked.
#[derive(Debug, Default)]
struct Parking {
    until: Option<Instant>,
}

impl Parking {
    fn park(&mut self, now: Instant) {
        self.until = Some(now + PARK_FOR);
    }

    fn parked(&self, now: Instant) -> bool {
        self.until.is_some_and(|until| now < until)
    }
}

static PARKING: Mutex<Parking> = Mutex::new(Parking { until: None });

fn parking() -> std::sync::MutexGuard<'static, Parking> {
    // Nothing is left half-written by a panic here: every change is one assignment.
    PARKING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Leave HTTP/3 alone for [`PARK_FOR`].
pub fn park(now: Instant) {
    parking().park(now);
}

/// Let the next attempt try HTTP/3 again: the line changed, or someone asked for a reconnect.
pub fn unpark() {
    parking().until = None;
}

/// Whether HTTP/3 is being left alone right now.
pub fn parked(now: Instant) -> bool {
    parking().parked(now)
}

/// What one attempt tries, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Only(Carrier),
    /// HTTP/3, and HTTP/2 in the same attempt if it does not open.
    H3ThenH2,
}

/// Decide what an attempt tries.
///
/// The split strategies are experiments on where TCP segments fall, so they only mean anything on
/// HTTP/2, whatever was chosen. The command line refuses `--transport h3` beside one of them; this
/// is what holds when the two are set separately.
pub fn plan(choice: Choice, handshake: Handshake, parked: bool) -> Plan {
    if !handshake.works_over_quic() {
        return Plan::Only(Carrier::H2);
    }
    match choice {
        Choice::H2 => Plan::Only(Carrier::H2),
        Choice::H3 => Plan::Only(Carrier::H3),
        Choice::Auto if parked => Plan::Only(Carrier::H2),
        Choice::Auto => Plan::H3ThenH2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_choice_round_trips_through_its_written_name() {
        for choice in Choice::ALL {
            assert_eq!(Choice::parse(choice.name()), Some(choice));
            assert_eq!(Choice::from_code(choice.code()), choice);
        }
        assert_eq!(Choice::parse("quic"), None);
    }

    /// The default is what every installation puts on the wire, so it is held here.
    #[test]
    fn a_run_starts_on_http3_with_http2_behind_it() {
        assert_eq!(selected(), Choice::Auto);
        assert_eq!(
            plan(Choice::Auto, Handshake::Fronted, false),
            Plan::H3ThenH2
        );
    }

    #[test]
    fn the_plan_follows_the_choice_and_the_parking() {
        let fronted = Handshake::Fronted;
        assert_eq!(plan(Choice::Auto, fronted, true), Plan::Only(Carrier::H2));
        assert_eq!(plan(Choice::H3, fronted, true), Plan::Only(Carrier::H3));
        assert_eq!(plan(Choice::H2, fronted, false), Plan::Only(Carrier::H2));
    }

    /// Cutting a ClientHello across TCP segments has nothing to cut over QUIC.
    #[test]
    fn a_split_handshake_always_rides_http2() {
        for split in [Handshake::Split, Handshake::SplitSlow] {
            for choice in Choice::ALL {
                assert_eq!(plan(choice, split, false), Plan::Only(Carrier::H2));
            }
        }
    }

    #[test]
    fn parking_lasts_as_long_as_it_says() {
        let now = Instant::now();
        let mut parking = Parking::default();
        assert!(!parking.parked(now));
        parking.park(now);
        assert!(parking.parked(now));
        assert!(parking.parked(now + PARK_FOR - Duration::from_secs(1)));
        assert!(!parking.parked(now + PARK_FOR));
    }
}
