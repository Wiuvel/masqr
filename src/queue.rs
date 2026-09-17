//! Flow queueing and CoDel on the way INTO the tunnel.
//!
//! This is the upload path only: packets read from the adapter, waiting to be written to the
//! endpoint. Nothing queues in the other direction — `pump`'s inward half writes each packet
//! straight to the adapter.
//!
//! **Measured 2026-09-04, and it has not engaged yet.** Twenty minutes of video and browsing put
//! 223.7 MiB in and 9.8 MiB out; every counter here stayed at zero and `worst_wait` never reached
//! one millisecond. At a 23:1 ratio the constrained direction was not this one, and at roughly a
//! hundred packets a second outbound the queue had nothing to hold. So the machinery below is
//! correct and tested but unproven in the field: it engages when upload is what saturates — a
//! large upload, a call, a genuinely narrow uplink — and not before.
//!
//! `fq_codel` is the standard answer for that case, in two halves.
//!
//! **Flow queueing.** Packets are filed into buckets by 5-tuple and served by deficit round-robin,
//! so a flow can only hold up itself. A bucket that was empty is served *before* the backlogged
//! ones — the half that fixes the symptom, since every new request is a new flow.
//!
//! Never within a flow: each bucket is a FIFO, because inner TCP reads reordering as loss.
//!
//! **CoDel.** A packet waiting longer than the target, for longer than the interval, is told to
//! slow down — marked if it carries ECT, dropped otherwise — at a rate rising with the square root
//! of how long the queue refuses to drain. Dropping inside a tunnel that could buffer instead is
//! the point rather than a compromise:
//!
//! > Over HTTP/2 the outer TCP delivers everything reliably, so the connections *inside* the
//! > tunnel never see loss and never back off. They see only growing delay. This is where their
//! > congestion signal has to come from.
//!
//! Over HTTP/3 the outer transport loses what the path loses, so the inner connections do hear
//! from the path — but QUIC paces datagrams to its own congestion window and holds the excess in a
//! buffer that is a plain FIFO. That buffer is kept small (`transport/quic.rs`), which leaves the
//! backlog here, where it is served per flow and CoDel decides what it costs.
//!
//! Constants are `fq_codel`'s published defaults, and the interval is then measured; see
//! [`Inner::observe_rtt`].

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// How long the target has to be exceeded before dropping starts, and the base of the drop-rate
/// control law afterwards.
///
/// CoDel's own default, and the value this starts at. It is meant to be about the round trip of the
/// traffic being managed, which is why [`Inner::observe_rtt`] moves it: a measurement beats a
/// constant, and the constant is only right for the paths it was chosen against.
const INTERVAL: Duration = Duration::from_millis(100);

/// The bounds a measured interval is held inside. Below the floor CoDel acts on ordinary jitter;
/// above the ceiling it stops acting on delay long enough to notice.
const INTERVAL_FLOOR: Duration = Duration::from_millis(50);
const INTERVAL_CEILING: Duration = Duration::from_millis(300);

/// What a measured tunnel round trip is multiplied by to get the interval.
///
/// The tunnel leg is one part of the path each inner connection takes, and the rest of it — exit to
/// server and back — cannot be seen from here. So the measurement is a floor on the round trip that
/// matters, and using it unscaled would make CoDel act on delay that was never standing. Four is
/// chosen so that an ordinary tunnel leg of 25 ms reproduces the 100 ms default exactly.
const RTT_TO_INTERVAL: u32 = 4;

/// How much of the interval a packet may spend waiting before it counts against the queue. CoDel's
/// rule of thumb is five to ten percent, and its own defaults are 5 ms against 100 ms.
const TARGET_SHARE: u32 = 20;

/// Bytes a flow may send per turn. One MTU, so a turn is one packet for the flows that send full
/// ones and several for the flows that send small ones.
const QUANTUM: usize = 1280;

/// How many buckets flows are filed into. Collisions cost fairness between the two flows that
/// collide and nothing else, so this is a memory choice rather than a correctness one.
const FLOWS: usize = 64;

/// The hard ceiling, for the case CoDel cannot answer: a burst arriving faster than the tunnel can
/// possibly drain it. Overflow is taken from the fattest bucket, never from the newest packet, so a
/// flood cannot push out the small flows it is drowning.
const LIMIT_BYTES: usize = 2 * 1024 * 1024;

/// How long a packet may have waited for a tunnel before it is no longer worth sending on one.
///
/// While there is no tunnel nothing drains the queue, and what fills it is soon out of date: a TCP
/// sender resends a segment once a second has gone unacknowledged, and a resolver asks again after
/// about the same. Sent on the fresh tunnel, the old copies arrive beside the new ones and spend its
/// first moments on duplicates. One second is RFC 6298's initial retransmission timeout.
const STALE_AFTER: Duration = Duration::from_secs(1);

/// A packet, and when it was put here. The time is what CoDel measures; nothing else reads it.
struct Queued {
    packet: Vec<u8>,
    at: Instant,
}

/// One bucket: a FIFO of packets, its round-robin credit, and its CoDel state.
#[derive(Default)]
struct Flow {
    packets: VecDeque<Queued>,
    bytes: usize,
    deficit: isize,
    /// Whether this bucket is on one of the two service lists. Listed while it has packets and
    /// unlisted the moment it runs dry, so its next packet makes it new again.
    listed: bool,
    /// When the sojourn time first went above target, plus one interval. `None` means it is under.
    above_since: Option<Instant>,
    /// When the next drop is due while dropping.
    drop_next: Option<Instant>,
    /// How many drops the current episode has made. Carried across episodes, so a queue that keeps
    /// coming back gets its delay under control faster each time.
    count: u32,
    dropping: bool,
}

/// What the queue has been doing. Read for the journal; nothing acts on it.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct QueueStats {
    /// Waiting right now.
    pub packets: usize,
    pub bytes: usize,
    /// Buckets with anything in them right now.
    pub flows: usize,
    /// Dropped because the queue was full — the tunnel could not keep up at all.
    pub over_limit: u64,
    /// Dropped by CoDel: the queue was draining, but not fast enough to stay under target.
    pub over_target: u64,
    /// Told to slow down without being dropped, because the sender asked to be told that way.
    pub marked: u64,
    /// Acknowledgements removed as redundant before they were ever sent.
    pub thinned: u64,
    /// Dropped when a tunnel came up, having waited for one longer than their senders wait before
    /// sending again.
    pub stale: u64,
    /// What CoDel is currently working to, which moves with the measured round trip.
    pub interval: Duration,
    /// The longest a delivered packet waited. Reset by each read, so it describes the interval.
    pub worst_wait: Duration,
}

struct Inner {
    flows: Vec<Flow>,
    /// Buckets that were empty when their last packet arrived. Served first: a flow that has just
    /// started is a request waiting for its first byte, and it is cheap to let it go ahead.
    fresh: VecDeque<usize>,
    /// Buckets that have been backlogged for at least one turn.
    backlogged: VecDeque<usize>,
    bytes: usize,
    packets: usize,
    over_limit: u64,
    over_target: u64,
    marked: u64,
    thinned: u64,
    stale: u64,
    worst_wait: Duration,
    /// CoDel's interval, and the share of it a packet may wait. Both move with the measured round
    /// trip; see [`Inner::observe_rtt`].
    interval: Duration,
    target: Duration,
    closed: bool,
}

/// The queue. One producer (the thread reading the adapter) and one consumer (the tunnel).
pub struct PacketQueue {
    inner: Mutex<Inner>,
    ready: Notify,
}

impl Default for PacketQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketQueue {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                flows: (0..FLOWS).map(|_| Flow::default()).collect(),
                fresh: VecDeque::new(),
                backlogged: VecDeque::new(),
                bytes: 0,
                packets: 0,
                over_limit: 0,
                over_target: 0,
                marked: 0,
                thinned: 0,
                stale: 0,
                worst_wait: Duration::ZERO,
                interval: INTERVAL,
                target: INTERVAL / TARGET_SHARE,
                closed: false,
            }),
            ready: Notify::new(),
        }
    }

    /// Take a packet, or drop it and say so.
    ///
    /// Never blocks and never waits. The thread calling this is inside the adapter's driver, and
    /// blocking it would let the driver's own ring fill instead — the same packets lost, but
    /// without a count and without the choice of WHICH to lose.
    pub fn push(&self, packet: Vec<u8>) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("queue lock");
        if inner.closed {
            return false;
        }
        inner.enqueue(packet, now);
        drop(inner);
        self.ready.notify_one();
        true
    }

    /// Fill `out` with up to `max` packets, waiting until there is at least one.
    ///
    /// A batch rather than a packet because everything downstream is cheaper in batches: over
    /// HTTP/2 several packets become one capsule run, one TLS record and one write instead of one
    /// of each apiece, and either way the queue is locked and woken once per batch.
    ///
    /// `false` means the adapter side has gone and nothing more is coming.
    pub async fn pop_batch(&self, out: &mut Vec<Vec<u8>>, max: usize) -> bool {
        out.clear();
        loop {
            {
                let mut inner = self.inner.lock().expect("queue lock");
                let now = Instant::now();
                while out.len() < max {
                    match inner.dequeue(now) {
                        Some(packet) => out.push(packet),
                        None => break,
                    }
                }
                if !out.is_empty() {
                    return true;
                }
                if inner.closed {
                    return false;
                }
            }
            self.ready.notified().await;
        }
    }

    /// Take a round trip measured on the tunnel itself, so CoDel works to this link rather than to
    /// the one its defaults were chosen against.
    pub fn observe_rtt(&self, rtt: Duration) {
        self.inner.lock().expect("queue lock").observe_rtt(rtt);
    }

    /// Drop what waited longer than [`STALE_AFTER`], and say how many. Called as a tunnel comes up,
    /// when the queue may be holding everything that arrived while there was none.
    pub fn drop_stale(&self) -> usize {
        self.inner
            .lock()
            .expect("queue lock")
            .drop_older_than(Instant::now(), STALE_AFTER)
    }

    /// Read the counters, and reset the ones that describe an interval rather than a level.
    pub fn stats(&self) -> QueueStats {
        let mut inner = self.inner.lock().expect("queue lock");
        let stats = QueueStats {
            packets: inner.packets,
            bytes: inner.bytes,
            flows: inner.flows.iter().filter(|f| !f.packets.is_empty()).count(),
            over_limit: inner.over_limit,
            over_target: inner.over_target,
            marked: inner.marked,
            thinned: inner.thinned,
            stale: inner.stale,
            interval: inner.interval,
            worst_wait: inner.worst_wait,
        };
        inner.worst_wait = Duration::ZERO;
        stats
    }

    /// The adapter side has ended. Wakes the consumer so it sees it rather than waiting forever.
    pub fn close(&self) {
        self.inner.lock().expect("queue lock").closed = true;
        self.ready.notify_one();
    }
}

impl Inner {
    fn enqueue(&mut self, packet: Vec<u8>, now: Instant) {
        let len = packet.len();
        while self.bytes + len > LIMIT_BYTES {
            if !self.drop_fattest() {
                break;
            }
        }
        let idx = flow_of(&packet);
        if let Some(acked) = pure_ack(&packet) {
            self.thin_acks(idx, &packet, acked);
        }
        let flow = &mut self.flows[idx];
        flow.packets.push_back(Queued { packet, at: now });
        flow.bytes += len;
        self.bytes += len;
        self.packets += 1;
        if !flow.listed {
            flow.listed = true;
            flow.deficit = QUANTUM as isize;
            self.fresh.push_back(idx);
        }
    }

    /// Drop acknowledgements this one has made redundant.
    ///
    /// A later acknowledgement covers everything an earlier one did, and where upstream is the
    /// narrow direction, sending all of them is most of what fills it. `sch_cake`'s ack filter,
    /// with its three rules:
    ///
    /// * Only when the newer one acknowledges **strictly more**. A repeat is a duplicate, and
    ///   duplicates are how a sender learns to retransmit before its timer fires.
    /// * The most recent redundant one stays, so two are always in flight and one lost
    ///   acknowledgement costs nothing.
    /// * Only ones with no options: selective-ack blocks and timestamps are not repeated by a
    ///   later plain acknowledgement.
    ///
    /// Buckets are shared by hashing, so the connection is compared, not assumed.
    fn thin_acks(&mut self, idx: usize, newer: &[u8], acked: u32) {
        let mut redundant: Vec<usize> = Vec::new();
        for (at, queued) in self.flows[idx].packets.iter().enumerate() {
            let Some(older) = pure_ack(&queued.packet) else {
                continue;
            };
            // Wrapping subtraction, because sequence numbers wrap: what is being asked is whether
            // `acked` is ahead of `older`, not whether it is the larger number.
            if acked.wrapping_sub(older) as i32 > 0 && same_connection(newer, &queued.packet) {
                redundant.push(at);
            }
        }
        // The newest redundant one is left where it is; only what is behind it goes.
        redundant.pop();
        // Back to front, so the positions still ahead of each removal stay valid.
        for at in redundant.into_iter().rev() {
            let Some(dropped) = self.flows[idx].packets.remove(at) else {
                continue;
            };
            self.flows[idx].bytes -= dropped.packet.len();
            self.bytes -= dropped.packet.len();
            self.packets -= 1;
            self.thinned += 1;
        }
    }

    /// Make room by taking the head of the longest bucket. `false` when there was nothing to take.
    ///
    /// The longest, because that is the flow responsible for the queue being full; dropping the
    /// arriving packet instead would punish whoever happened to be unlucky, which on a queue held
    /// full by one download is everyone else.
    fn drop_fattest(&mut self) -> bool {
        let Some((idx, _)) = self
            .flows
            .iter()
            .enumerate()
            .map(|(i, f)| (i, f.bytes))
            .max_by_key(|(_, bytes)| *bytes)
            .filter(|(_, bytes)| *bytes > 0)
        else {
            return false;
        };
        let flow = &mut self.flows[idx];
        if let Some(dropped) = flow.packets.pop_front() {
            flow.bytes -= dropped.packet.len();
            self.bytes -= dropped.packet.len();
            self.packets -= 1;
            self.over_limit += 1;
        }
        true
    }

    /// Take every packet that has waited `age` or longer.
    ///
    /// A bucket is a FIFO, so its old packets are the ones at its head, and what is left keeps its
    /// order. A bucket emptied this way stays listed until the scheduler reaches it and finds it
    /// dry, as one drained by delivery does.
    ///
    /// Each bucket's CoDel state is also cleared of standing delay: the delay was the gap between
    /// tunnels, and read against the new one it would start dropping the moment it came up.
    fn drop_older_than(&mut self, now: Instant, age: Duration) -> usize {
        let mut dropped = 0;
        for flow in &mut self.flows {
            while flow
                .packets
                .front()
                .is_some_and(|head| now.saturating_duration_since(head.at) >= age)
            {
                let Some(old) = flow.packets.pop_front() else {
                    break;
                };
                flow.bytes -= old.packet.len();
                self.bytes -= old.packet.len();
                self.packets -= 1;
                dropped += 1;
            }
            flow.above_since = None;
            flow.dropping = false;
        }
        self.stale += dropped as u64;
        dropped
    }

    /// The next packet to send, chosen between flows and filtered by CoDel within one.
    fn dequeue(&mut self, now: Instant) -> Option<Vec<u8>> {
        loop {
            // Fresh flows first, and only then the ones already backlogged. A bucket taken from
            // `fresh` that turns out to be empty goes to the back of `backlogged` rather than being
            // dropped from service: it has had its head start, and it is now an ordinary flow.
            let (idx, was_fresh) = match self.fresh.front().copied() {
                Some(idx) => (idx, true),
                None => (self.backlogged.front().copied()?, false),
            };

            if self.flows[idx].deficit <= 0 {
                self.flows[idx].deficit += QUANTUM as isize;
                if was_fresh {
                    self.fresh.pop_front();
                } else {
                    self.backlogged.pop_front();
                }
                self.backlogged.push_back(idx);
                continue;
            }

            match self.codel(idx, now) {
                Some(packet) => {
                    self.flows[idx].deficit -= packet.len() as isize;
                    return Some(packet);
                }
                None => {
                    // Ran dry. Unlisted, so its next packet makes it fresh again — which is what
                    // makes "a flow that has just started" mean something.
                    if was_fresh {
                        self.fresh.pop_front();
                    } else {
                        self.backlogged.pop_front();
                    }
                    self.flows[idx].listed = false;
                }
            }
        }
    }

    /// Take the head of one bucket, and say whether the queue has been standing too long.
    ///
    /// The second half of the test is what stops CoDel acting on a queue that is merely a packet or
    /// two deep: a burst below one quantum is not standing delay, it is the link being used.
    fn take(&mut self, idx: usize, now: Instant) -> Option<(Vec<u8>, bool)> {
        let head = self.flows[idx].packets.pop_front()?;
        let len = head.packet.len();
        let waited = now.saturating_duration_since(head.at);

        self.flows[idx].bytes -= len;
        self.bytes -= len;
        self.packets -= 1;
        // Recorded for every packet that leaves, dropped or delivered: what it measures is how long
        // this queue was making packets wait, and a dropped one waited just as long.
        self.worst_wait = self.worst_wait.max(waited);

        // Standing delay, not a burst: over target AND still more than a quantum behind it.
        let standing = waited >= self.target && self.flows[idx].bytes > QUANTUM;
        let overdue = match (standing, self.flows[idx].above_since) {
            (false, _) => {
                self.flows[idx].above_since = None;
                false
            }
            (true, None) => {
                self.flows[idx].above_since = Some(now + self.interval);
                false
            }
            (true, Some(due)) => now >= due,
        };
        Some((head.packet, overdue))
    }

    /// CoDel proper: deliver the head, unless the queue has been standing — in which case the head
    /// carries the congestion signal away, either as a mark it keeps or by not being delivered.
    ///
    /// Which of the two is the sender's choice, not ours: a sender that set ECT has said it would
    /// rather be told than lose the packet, and telling it costs nothing — the packet arrives, the
    /// sender slows down, and nothing is retransmitted. A sender that said nothing is told the only
    /// other way there is.
    fn codel(&mut self, idx: usize, now: Instant) -> Option<Vec<u8>> {
        let (mut packet, mut overdue) = self.take(idx, now)?;

        if self.flows[idx].dropping {
            if !overdue {
                self.flows[idx].dropping = false;
            } else {
                while self.flows[idx].dropping && self.due(idx, now) {
                    self.flows[idx].count += 1;
                    if self.mark(&mut packet) {
                        let from = self.flows[idx].drop_next.unwrap_or(now);
                        self.schedule(idx, from);
                        return Some(packet);
                    }
                    self.over_target += 1;
                    let Some(next) = self.take(idx, now) else {
                        self.flows[idx].dropping = false;
                        return None;
                    };
                    (packet, overdue) = next;
                    if overdue {
                        let from = self.flows[idx].drop_next.unwrap_or(now);
                        self.schedule(idx, from);
                    } else {
                        self.flows[idx].dropping = false;
                    }
                }
            }
        } else if overdue {
            let marked = self.mark(&mut packet);
            let next = if marked {
                None
            } else {
                self.over_target += 1;
                self.take(idx, now)
            };
            let interval = self.interval;
            let flow = &mut self.flows[idx];
            // Coming back soon after the last episode means the queue never really recovered, so
            // the drop rate resumes near where it left off rather than from the beginning. Sixteen
            // intervals is CoDel's own figure for "soon".
            let resumed = flow
                .drop_next
                .is_some_and(|last| now.saturating_duration_since(last) < 16 * interval);
            flow.count = if flow.count > 2 && resumed {
                flow.count - 2
            } else {
                1
            };
            flow.dropping = true;
            self.schedule(idx, now);
            if !marked {
                packet = next?.0;
            }
        }
        Some(packet)
    }

    /// Put the congestion signal inside the packet, if it says it can carry one.
    fn mark(&mut self, packet: &mut [u8]) -> bool {
        if !mark_congestion(packet) {
            return false;
        }
        self.marked += 1;
        true
    }

    fn due(&self, idx: usize, now: Instant) -> bool {
        self.flows[idx].drop_next.is_some_and(|next| now >= next)
    }

    /// The control law: drops come `interval / sqrt(count)` apart, so the rate rises as the square
    /// root of how long the queue has refused to drain.
    fn schedule(&mut self, idx: usize, from: Instant) {
        let interval = self.interval;
        let flow = &mut self.flows[idx];
        flow.drop_next = Some(from + interval.div_f64(f64::from(flow.count.max(1)).sqrt()));
    }

    /// Take a round trip measured on the tunnel itself, and work CoDel to it.
    ///
    /// Smoothed rather than taken as read: one sample every few seconds is noisy, and an interval
    /// that jumps with it would make the queue behave differently for no reason a person could see.
    /// A seven-eighths average settles over about a minute, which is slower than a route change and
    /// faster than a link staying different.
    fn observe_rtt(&mut self, rtt: Duration) {
        let scaled = rtt * RTT_TO_INTERVAL;
        let blended = (self.interval * 7 + scaled) / 8;
        self.interval = blended.clamp(INTERVAL_FLOOR, INTERVAL_CEILING);
        self.target = self.interval / TARGET_SHARE;
    }
}

/// Where the transport header starts, and which protocol it is, for a packet this queue can read.
///
/// IPv6 extension headers are not walked: a packet carrying them is reported as unreadable rather
/// than guessed at, which costs it the treatment below and nothing else.
fn transport(packet: &[u8]) -> Option<(usize, u8)> {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            (header >= 20 && packet.len() >= header).then_some((header, packet[9]))
        }
        Some(6) if packet.len() >= 40 => Some((40, packet[6])),
        _ => None,
    }
}

/// Whether two packets belong to the same connection, compared rather than assumed: buckets are
/// shared by hashing, so two connections can be sitting in one.
fn same_connection(a: &[u8], b: &[u8]) -> bool {
    let (Some((a_at, a_proto)), Some((b_at, b_proto))) = (transport(a), transport(b)) else {
        return false;
    };
    if a_proto != b_proto || a[0] >> 4 != b[0] >> 4 {
        return false;
    }
    let addresses = if a[0] >> 4 == 4 { 12..20 } else { 8..40 };
    a[addresses.clone()] == b[addresses]
        && a.len() >= a_at + 4
        && b.len() >= b_at + 4
        && a[a_at..a_at + 4] == b[b_at..b_at + 4]
}

/// The acknowledgement number of a packet that is an acknowledgement and nothing else.
///
/// Deliberately strict. Exactly the ACK flag — a packet also carrying SYN, FIN, RST, PUSH or either
/// congestion flag is saying something of its own. No payload. And no options, which keeps
/// selective acknowledgements and timestamps out of reach of anything that acts on this.
fn pure_ack(packet: &[u8]) -> Option<u32> {
    const ACK_ONLY: u8 = 0x10;
    const NO_OPTIONS: u8 = 5 << 4;
    let (at, proto) = transport(packet)?;
    if proto != 6 || packet.len() < at + 20 {
        return None;
    }
    let tcp = &packet[at..];
    if tcp[12] != NO_OPTIONS || tcp[13] != ACK_ONLY || packet.len() != at + 20 {
        return None;
    }
    Some(u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]))
}

/// Set the congestion mark, and say whether the packet was willing to carry it.
///
/// A sender that left the field at zero has not asked to be told this way, and marking it would be
/// a signal nothing reads — the packet has to be dropped instead.
fn mark_congestion(packet: &mut [u8]) -> bool {
    match packet.first().map(|b| b >> 4) {
        // The low two bits of the type-of-service byte, and a header checksum to put back.
        Some(4) if packet.len() >= 20 => {
            if packet[1] & 0b11 == 0 {
                return false;
            }
            if packet[1] & 0b11 == 0b11 {
                return true;
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20 || packet.len() < header {
                return false;
            }
            packet[1] |= 0b11;
            let sum = crate::ip::ipv4_checksum(&packet[..header]);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
            true
        }
        // The traffic class straddles two bytes; its low two bits are bits 4 and 5 of the second.
        // Nothing to recompute — an IPv6 header carries no checksum of its own.
        Some(6) if packet.len() >= 40 => {
            if packet[1] & 0b0011_0000 == 0 {
                return false;
            }
            packet[1] |= 0b0011_0000;
            true
        }
        _ => false,
    }
}

/// Which bucket a packet belongs in: its 5-tuple, hashed.
///
/// Extension headers on IPv6 are not walked. Getting the ports wrong for those files a flow under
/// the wrong bucket, which costs fairness between two flows and nothing else — and the packets of
/// one flow still hash alike, which is the property that matters.
fn flow_of(packet: &[u8]) -> usize {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x100_0000_01b3;
    let mut hash = OFFSET;
    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
    };

    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let protocol = packet[9];
            eat(&packet[12..20]);
            eat(&[protocol]);
            let header = usize::from(packet[0] & 0x0f) * 4;
            if matches!(protocol, 6 | 17) && packet.len() >= header + 4 {
                eat(&packet[header..header + 4]);
            }
        }
        Some(6) if packet.len() >= 40 => {
            let protocol = packet[6];
            eat(&packet[8..40]);
            eat(&[protocol]);
            if matches!(protocol, 6 | 17) && packet.len() >= 44 {
                eat(&packet[40..44]);
            }
        }
        // Not IP, or too short to read. One bucket for all of them: they are rare, and giving them
        // their own fair share is not worth a second rule.
        _ => eat(&[0]),
    }
    (hash % FLOWS as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two flows every test below uses. Their ports are not arbitrary: they were chosen to land
    /// in different buckets, which `two_flows_that_the_tests_can_tell_apart` holds them to. Ports
    /// that collide would make a fairness test compare a flow against itself — and pass.
    pub(super) const BULK: u16 = 1000;
    pub(super) const SPARSE: u16 = 3000;

    /// A TCP packet of `len` bytes from one of the two test flows.
    ///
    /// The tag byte sits past the ports on purpose: anything written inside the 5-tuple changes the
    /// bucket, so a test that marked packets there would be filing each one somewhere else.
    pub(super) fn packet(port: u16, len: usize, tag: u8) -> Vec<u8> {
        let mut packet = vec![0u8; len.max(25)];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&if port == BULK {
            [1, 1, 1, 1]
        } else {
            [2, 2, 2, 2]
        });
        packet[20..22].copy_from_slice(&port.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24] = tag;
        packet
    }

    /// Dequeue up to `max` packets at one instant, bypassing the async wrapper.
    pub(super) fn drain(queue: &PacketQueue, max: usize) -> Vec<Vec<u8>> {
        let mut inner = queue.inner.lock().unwrap();
        let now = Instant::now();
        let mut out = Vec::new();
        while out.len() < max {
            match inner.dequeue(now) {
                Some(packet) => out.push(packet),
                None => break,
            }
        }
        out
    }

    /// Which flow each dequeued packet came from.
    pub(super) fn ports(packets: &[Vec<u8>]) -> Vec<u16> {
        packets
            .iter()
            .map(|p| u16::from_be_bytes([p[20], p[21]]))
            .collect()
    }

    #[test]
    fn two_flows_that_the_tests_can_tell_apart() {
        assert_ne!(
            flow_of(&packet(BULK, 100, 0)),
            flow_of(&packet(SPARSE, 100, 0)),
            "the test flows share a bucket, so nothing below measures fairness"
        );
    }

    #[test]
    fn one_flow_keeps_its_order() {
        // Fairness is between flows only. Inner TCP reads reordering as loss, so a bucket has to
        // stay a FIFO — this is the property that must survive every change to the scheduler.
        let queue = PacketQueue::new();
        for tag in 0..8u8 {
            queue.push(packet(BULK, 100, tag));
        }
        let out = drain(&queue, 8);
        assert_eq!(
            out.iter().map(|p| p[24]).collect::<Vec<_>>(),
            (0..8u8).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_new_flow_goes_ahead_of_a_backlog() {
        // The symptom this queue exists for: a page of small requests behind a download. The
        // request arrives last and must not leave last.
        let queue = PacketQueue::new();
        for tag in 0..20u8 {
            queue.push(packet(BULK, 1200, tag));
        }
        // Enough turns that the download has spent its head start and become an ordinary flow.
        drain(&queue, 3);
        queue.push(packet(SPARSE, 60, 0));

        assert_eq!(ports(&drain(&queue, 1)), vec![SPARSE]);
    }

    #[test]
    fn neither_of_two_busy_flows_is_starved() {
        let queue = PacketQueue::new();
        for tag in 0..10u8 {
            queue.push(packet(BULK, 1300, tag));
            queue.push(packet(SPARSE, 1300, tag));
        }
        let out = ports(&drain(&queue, 12));
        let bulk = out.iter().filter(|p| **p == BULK).count();
        // Round-robin over a deficit does not alternate packet by packet: with packets larger
        // than the quantum a flow can take two turns before yielding. What it may never do is let
        // one flow run away with the queue, which is what this asserts.
        assert!(
            (4..=8).contains(&bulk),
            "one flow took {bulk} of 12 turns: {out:?}"
        );
    }

    #[test]
    fn a_flood_is_taken_from_the_flood_and_not_from_the_bystander() {
        // Overflow drops from the fattest bucket. Dropping the arriving packet instead would let
        // one download push out every small flow it is drowning.
        let queue = PacketQueue::new();
        queue.push(packet(SPARSE, 60, 0));
        while queue.stats().bytes + 1300 <= LIMIT_BYTES {
            queue.push(packet(BULK, 1300, 0));
        }
        for _ in 0..50 {
            queue.push(packet(BULK, 1300, 0));
        }

        assert!(queue.stats().over_limit > 0, "the limit never bit");
        assert_eq!(ports(&drain(&queue, 1)), vec![SPARSE]);
    }

    #[test]
    fn a_queue_that_stands_too_long_starts_dropping() {
        // CoDel's whole job, and why a tunnel drops at all: the outer TCP hides loss from the
        // connections inside it, so this is the only place their congestion signal can come from.
        let queue = PacketQueue::new();
        let mut inner = queue.inner.lock().unwrap();
        let start = Instant::now();
        for tag in 0..40u8 {
            inner.enqueue(packet(BULK, 1300, tag), start);
        }

        // The first dequeue past target only starts the clock: CoDel drops nothing until the
        // target has been exceeded for a whole interval, so a burst does not count.
        let (target, interval) = (inner.target, inner.interval);
        let armed = start + target + Duration::from_millis(1);
        assert!(inner.dequeue(armed).is_some());
        assert_eq!(
            inner.over_target, 0,
            "a burst was treated as standing delay"
        );

        assert!(
            inner
                .dequeue(armed + interval + Duration::from_millis(1))
                .is_some()
        );
        assert!(inner.over_target > 0, "standing delay went unpunished");
    }

    #[test]
    fn a_queue_that_drains_promptly_is_left_alone() {
        let queue = PacketQueue::new();
        let mut inner = queue.inner.lock().unwrap();
        let start = Instant::now();
        for tag in 0..40u8 {
            inner.enqueue(packet(BULK, 1300, tag), start);
        }
        for step in 0..40 {
            inner.dequeue(start + Duration::from_micros(step * 10));
        }
        assert_eq!(inner.over_target, 0, "a fast queue was punished");
    }

    #[test]
    fn what_waited_out_a_gap_between_tunnels_is_not_sent_on_the_next() {
        let queue = PacketQueue::new();
        let mut inner = queue.inner.lock().unwrap();
        let start = Instant::now();
        for tag in 0..10u8 {
            inner.enqueue(packet(BULK, 1300, tag), start);
        }
        inner.enqueue(packet(SPARSE, 100, 0), start);
        let later = start + STALE_AFTER;
        for tag in 10..13u8 {
            inner.enqueue(packet(BULK, 1300, tag), later);
        }

        assert_eq!(inner.drop_older_than(later, STALE_AFTER), 11);
        assert_eq!((inner.packets, inner.bytes, inner.stale), (3, 3 * 1300, 11));

        // The standing delay was the gap, and it is not held against the tunnel that ends it: the
        // next dequeues at the new tunnel's pace deliver what is left, in order, and drop nothing.
        let mut delivered = Vec::new();
        while let Some(packet) = inner.dequeue(later + Duration::from_millis(1)) {
            delivered.push(packet[24]);
        }
        assert_eq!(delivered, vec![10, 11, 12]);
        assert_eq!(inner.over_target, 0);
    }

    #[test]
    fn the_bucket_follows_the_five_tuple_and_nothing_else() {
        let short = flow_of(&packet(BULK, 60, 0));
        let long = flow_of(&packet(BULK, 1200, 7));
        assert_eq!(short, long, "size or payload changed the bucket");
    }

    #[tokio::test]
    async fn a_closed_queue_delivers_what_is_left_and_then_says_so() {
        let queue = PacketQueue::new();
        queue.push(packet(BULK, 60, 0));
        queue.close();
        let mut out = Vec::new();
        assert!(queue.pop_batch(&mut out, 16).await);
        assert_eq!(out.len(), 1);
        assert!(!queue.pop_batch(&mut out, 16).await);
    }
}

#[cfg(test)]
mod signals {
    use super::tests::{BULK, SPARSE, drain, packet, ports};
    use super::*;

    /// A bare acknowledgement: twenty bytes of IP, twenty of TCP, no options and no payload.
    fn ack(port: u16, acked: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&if port == BULK {
            [1, 1, 1, 1]
        } else {
            [2, 2, 2, 2]
        });
        packet[20..22].copy_from_slice(&port.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[28..32].copy_from_slice(&acked.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x10;
        seal(packet)
    }

    /// Put the header checksum right, so a test can tell a changed header from a wrong one.
    fn seal(mut packet: Vec<u8>) -> Vec<u8> {
        let sum = crate::ip::ipv4_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    fn checksum_holds(packet: &[u8]) -> bool {
        let stored = u16::from_be_bytes([packet[10], packet[11]]);
        crate::ip::ipv4_checksum(&packet[..20]) == stored
    }

    /// The same packet, from a sender that asked to be told rather than dropped.
    fn ecn_capable(mut packet: Vec<u8>) -> Vec<u8> {
        packet[1] |= 0b10;
        seal(packet)
    }

    fn acked(packet: &[u8]) -> u32 {
        u32::from_be_bytes([packet[28], packet[29], packet[30], packet[31]])
    }

    // ── telling a sender to slow down ────────────────────────────────────────

    #[test]
    fn a_sender_that_asked_to_be_told_is_told_and_not_dropped() {
        let mut packet = ecn_capable(ack(BULK, 1));
        assert!(mark_congestion(&mut packet));
        assert_eq!(packet[1] & 0b11, 0b11, "the mark is not set");
        assert!(checksum_holds(&packet), "the header no longer verifies");
    }

    #[test]
    fn a_sender_that_did_not_ask_is_left_for_dropping() {
        // Marking one of these would be a signal nothing reads, and the packet would go on adding
        // to the queue it was supposed to relieve.
        let mut packet = ack(BULK, 1);
        assert!(!mark_congestion(&mut packet));
        assert_eq!(packet[1] & 0b11, 0, "an unwilling packet was marked anyway");
    }

    #[test]
    fn an_already_marked_packet_is_left_exactly_as_it_is() {
        let mut packet = ecn_capable(ack(BULK, 1));
        assert!(mark_congestion(&mut packet));
        let once = packet.clone();
        assert!(mark_congestion(&mut packet));
        assert_eq!(packet, once, "marking twice changed the packet");
    }

    #[test]
    fn a_standing_queue_of_willing_senders_is_marked_rather_than_thinned() {
        let queue = PacketQueue::new();
        let mut inner = queue.inner.lock().unwrap();
        let start = Instant::now();
        for tag in 0..40u8 {
            inner.enqueue(ecn_capable(packet(BULK, 1300, tag)), start);
        }
        let armed = start + inner.target + Duration::from_millis(1);
        let interval = inner.interval;
        inner.dequeue(armed);
        inner.dequeue(armed + interval + Duration::from_millis(1));

        assert!(inner.marked > 0, "nothing was told to slow down");
        assert_eq!(inner.over_target, 0, "a willing sender was dropped anyway");
    }

    // ── acknowledgements ─────────────────────────────────────────────────────

    #[test]
    fn a_later_acknowledgement_makes_the_earlier_ones_pointless() {
        // Everything an earlier one says, a later one says too. On a link whose narrow direction is
        // upstream, sending all of them is most of what fills it.
        let queue = PacketQueue::new();
        for n in 1..=5u32 {
            queue.push(ack(BULK, n * 1000));
        }
        let left = drain(&queue, 8);
        // The newest, and one behind it: a single lost acknowledgement then costs nothing.
        assert_eq!(
            left.iter().map(|p| acked(p)).collect::<Vec<_>>(),
            vec![4000, 5000]
        );
        assert_eq!(queue.stats().thinned, 3);
    }

    #[test]
    fn a_repeated_acknowledgement_is_never_removed() {
        // Duplicates are how a sender learns to retransmit before its timer fires. Removing them
        // would take fast retransmit away from the connection.
        let queue = PacketQueue::new();
        for _ in 0..4 {
            queue.push(ack(BULK, 7000));
        }
        assert_eq!(queue.stats().thinned, 0);
        assert_eq!(drain(&queue, 8).len(), 4);
    }

    #[test]
    fn an_acknowledgement_carrying_options_is_left_alone() {
        // Selective acknowledgements and timestamps live in the options. A later plain one does not
        // repeat what they said, so it cannot stand in for them.
        let queue = PacketQueue::new();
        let mut with_options = ack(BULK, 1000);
        with_options[32] = 6 << 4; // a longer header, whatever is in it
        queue.push(seal(with_options));
        queue.push(ack(BULK, 2000));
        queue.push(ack(BULK, 3000));

        assert_eq!(
            queue.stats().thinned,
            0,
            "an option-carrying ack was removed"
        );
    }

    #[test]
    fn a_neighbour_sharing_the_bucket_is_not_thinned() {
        // Buckets are shared by hashing, so the connection is compared and not assumed. Removing
        // another connection's acknowledgements would be a silent hole in a healthy link.
        // Port 2000 was picked because it hashes into the same bucket as `BULK` — the collision is
        // the point, and the assertion below is what says it still happens.
        const NEIGHBOUR: u16 = 2000;
        let queue = PacketQueue::new();
        let mine = ack(BULK, 1000);
        let theirs = ack(NEIGHBOUR, 2000);
        assert_eq!(flow_of(&mine), flow_of(&theirs), "the test premise is gone");

        queue.push(mine);
        queue.push(theirs);
        queue.push(ack(BULK, 3000));
        assert_eq!(queue.stats().thinned, 0);
        assert_eq!(ports(&drain(&queue, 8)).len(), 3);
    }

    #[test]
    fn thinning_keeps_the_queue_totals_straight() {
        let queue = PacketQueue::new();
        for n in 1..=6u32 {
            queue.push(ack(SPARSE, n * 100));
        }
        let stats = queue.stats();
        assert_eq!(stats.packets, 2);
        assert_eq!(stats.bytes, 80, "bytes did not follow the packets out");
    }

    // ── working to the link that is there ────────────────────────────────────

    #[test]
    fn the_interval_follows_a_measured_round_trip() {
        let queue = PacketQueue::new();
        // An ordinary tunnel leg reproduces the published default, which is why the factor is what
        // it is: the constant is not being replaced, it is being derived.
        for _ in 0..40 {
            queue.observe_rtt(Duration::from_millis(25));
        }
        assert_eq!(queue.stats().interval, Duration::from_millis(100));

        for _ in 0..40 {
            queue.observe_rtt(Duration::from_millis(200));
        }
        assert_eq!(
            queue.stats().interval,
            INTERVAL_CEILING,
            "a slow link was not held at the ceiling"
        );

        for _ in 0..80 {
            queue.observe_rtt(Duration::from_micros(500));
        }
        assert_eq!(
            queue.stats().interval,
            INTERVAL_FLOOR,
            "a fast link was not held at the floor"
        );
    }

    #[test]
    fn the_target_stays_a_share_of_the_interval() {
        let queue = PacketQueue::new();
        for _ in 0..40 {
            queue.observe_rtt(Duration::from_millis(50));
        }
        let inner = queue.inner.lock().unwrap();
        assert_eq!(inner.target, inner.interval / TARGET_SHARE);
    }
}
