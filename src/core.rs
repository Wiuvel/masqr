//! State shared between the parts of the core.
//!
//! Three things outlive any one tunnel and are read by more than one task: how much has gone
//! through, what the engine is doing, and which prefixes are routed. They live here so the engine,
//! the control interface and the display read one answer rather than each keeping its own.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::dns::lease::Leases;
use crate::dns::server::RouteSink;
use crate::transport::Stages;
use crate::tun::{Adapter, Change, Prefix, Routes, TunError};

/// Packets and bytes in one direction.
#[derive(Default)]
pub struct Counter {
    packets: AtomicU64,
    bytes: AtomicU64,
}

impl Counter {
    pub(crate) fn record(&self, bytes: usize) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Packets and bytes so far.
    pub fn read(&self) -> (u64, u64) {
        (
            self.packets.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }
}

/// What has gone through, in both directions. Carried across reconnects, because it counts what the
/// tunnel has done for the machine, not what one connection did.
#[derive(Default)]
pub struct Counters {
    pub out: Counter,
    pub back: Counter,
}

/// The path under an HTTP/3 tunnel as QUIC last reported it, for the journal and the status.
///
/// `datagrams` and `read` together say where a packet lost on the way in went missing: a datagram
/// QUIC received and the tunnel never read was dropped by QUIC's receive buffer on this machine,
/// while `lost` counts this side's packets the path lost. Both are counted from when the tunnel
/// came up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathReading {
    pub rtt: Duration,
    /// Congestion window, bytes.
    pub cwnd: u64,
    /// QUIC packets sent, and how many of those the path lost.
    pub sent: u64,
    pub lost: u64,
    /// Datagrams QUIC received, and packets the tunnel read out of it.
    pub datagrams: u64,
    pub read: u64,
}

/// What the engine is doing.
#[derive(Debug, Clone)]
pub enum Phase {
    /// Opening a tunnel. `attempt` counts from one and resets whenever one comes up.
    Connecting { attempt: usize },
    /// A tunnel is up and carrying packets.
    Up { stages: Stages },
    /// There is no tunnel, and another attempt is coming.
    ///
    /// `blocked` separates the one failure a supervisor must treat differently: the handshake was
    /// cut with no reply, which is something on the way refusing rather than anything here being
    /// wrong. Retrying that is not what fixes it, so whatever drives this core needs to know it
    /// without reading the sentence.
    Lost {
        reason: String,
        retry_in: Duration,
        blocked: bool,
    },
}

impl Phase {
    /// One word for the state, for anything that has to name it rather than describe it.
    pub fn name(&self) -> &'static str {
        match self {
            Phase::Connecting { .. } => "connecting",
            Phase::Up { .. } => "up",
            Phase::Lost { .. } => "lost",
        }
    }
}

/// What is known about whether the tunnel carries IPv6.
///
/// Three states rather than two, because "not asked yet" and "asked, and it does not" call for
/// different things: the first is a reason to ask, and the second is an answer to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Support {
    Unknown,
    Carries,
    DoesNot,
}

/// The core's shared state.
///
/// The phase is a watch channel rather than a plain value on purpose: a control interface needs the
/// current one and a display needs to be told when it changes, and one channel serves both without
/// either polling.
pub struct Core {
    pub counters: Counters,
    pub phase: watch::Sender<Phase>,
    adapter: Adapter,
    routes: Mutex<Routes>,
    /// What the application asked for. Held separately from what is installed, because what is
    /// installed is this set together with whatever DNS has learned, and neither may erase the
    /// other when it changes.
    asked: Mutex<BTreeSet<Prefix>>,
    /// What DNS has learned. Addresses, with an expiry, that became routes because a name the
    /// policy claims resolved to them.
    leases: Arc<Leases>,
    stop: watch::Sender<bool>,
    reconnects: watch::Sender<u64>,
    /// Bumped when the line under the tunnel changed — an interface came up, went away, or stopped
    /// being the one packets leave by.
    line: watch::Sender<u64>,
    /// The interface the latest line change named, as a LUID (0 when it named none), and the kind
    /// of notification it was. Read only to say what changed.
    last_change_interface: AtomicU64,
    last_change_kind: AtomicI32,
    /// Whether the application wants IPv6 carried at all. Its decision, not this core's.
    wants_v6: AtomicBool,
    /// Whether the tunnel has been shown to carry it. This core's decision, and only ever made by
    /// measurement — see `probe.rs` for why assuming it is the one mistake that makes the working
    /// address family slower than it was before the tunnel existed.
    v6: AtomicU8,
    /// The line's address for each destination asked about, and when and for which line it was
    /// looked up. See [`RouteSink::line_source`].
    line_sources: Mutex<HashMap<IpAddr, LineSource>>,
    /// The path under the tunnel that is up, when it is an HTTP/3 one.
    path: Mutex<Option<PathReading>>,
}

/// How long a looked-up line address is trusted when the line has not been seen to change.
///
/// The interface notification is what normally retires one. This bounds the case it does not cover
/// — a route on another interface appearing without that interface changing — to half a minute, for
/// a lookup that walks the routing table and so is not done per query.
const LINE_SOURCE_TTL: Duration = Duration::from_secs(30);

/// One looked-up line address.
#[derive(Clone, Copy)]
struct LineSource {
    line: u64,
    at: Instant,
    from: Option<IpAddr>,
}

impl Core {
    /// Take ownership of an adapter and everything routed through it.
    pub fn new(adapter: Adapter) -> Self {
        Self {
            counters: Counters::default(),
            phase: watch::Sender::new(Phase::Connecting { attempt: 1 }),
            adapter,
            routes: Mutex::new(Routes::default()),
            asked: Mutex::new(BTreeSet::new()),
            leases: Arc::new(Leases::new()),
            stop: watch::Sender::new(false),
            reconnects: watch::Sender::new(0),
            line: watch::Sender::new(0),
            last_change_interface: AtomicU64::new(0),
            last_change_kind: AtomicI32::new(0),
            wants_v6: AtomicBool::new(false),
            v6: AtomicU8::new(Ipv6Support::Unknown as u8),
            line_sources: Mutex::new(HashMap::new()),
            path: Mutex::new(None),
        }
    }

    /// Record the latest reading of the path, or that there is none to read.
    pub fn set_path(&self, reading: Option<PathReading>) {
        *self
            .path
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = reading;
    }

    /// The latest reading of the path under an HTTP/3 tunnel, while one is up.
    pub fn path(&self) -> Option<PathReading> {
        *self
            .path
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The adapter this core owns. Dropping the core is what removes it from Windows.
    pub fn adapter(&self) -> &Adapter {
        &self.adapter
    }

    /// Replace what the application asks for, and make the routing table agree.
    ///
    /// This is only half of what ends up installed. The other half is what DNS has learned, and the
    /// two are unioned every time either changes — so a set arriving from the application never
    /// takes away an address a name is currently resolving to, and an expiring lease never takes
    /// away a prefix the application asked for.
    pub fn set_routes(&self, wanted: &BTreeSet<Prefix>) -> Result<Change, TunError> {
        *self.locked_asked() = wanted.clone();
        self.install_union()
    }

    /// Make the routing table agree with what is currently asked for and leased.
    pub fn refresh_routes(&self) -> Result<Change, TunError> {
        self.install_union()
    }

    /// Whether the application asked for IPv6 to be carried.
    pub fn set_wants_ipv6(&self, wanted: bool) {
        self.wants_v6.store(wanted, Ordering::Relaxed);
    }

    /// What is known about the tunnel and IPv6.
    pub fn ipv6_support(&self) -> Ipv6Support {
        match self.v6.load(Ordering::Relaxed) {
            1 => Ipv6Support::Carries,
            2 => Ipv6Support::DoesNot,
            _ => Ipv6Support::Unknown,
        }
    }

    /// Record what a measurement found, and make the routing table agree with it.
    pub fn set_carries_ipv6(&self, carries: bool) {
        let state = if carries {
            Ipv6Support::Carries
        } else {
            Ipv6Support::DoesNot
        };
        if self.ipv6_support() == state {
            return;
        }
        self.v6.store(state as u8, Ordering::Relaxed);
        notice!(
            "tunnel",
            "ipv6 {}",
            if carries {
                "is carried"
            } else {
                "is not carried; v6 stays on the line"
            }
        );
        let _ = self.refresh_routes();
    }

    /// Whether it is worth measuring again on this connect.
    ///
    /// Asymmetric on purpose. A stale "it carries v6" is the dangerous answer: it routes a family
    /// into a tunnel that black-holes it, and the machine picks that path first because the routing
    /// table said it was there. A stale "it does not" merely leaves v6 on the line, which is what
    /// the machine did before this core existed. So a yes is re-checked on every connect, and a no
    /// is kept — which also spares every reconnect the full wait when there is no v6 to find.
    pub fn should_probe_ipv6(&self) -> bool {
        self.ipv6_support() != Ipv6Support::DoesNot
    }

    /// Whether a v6 prefix may be installed: the application has to want it and the tunnel has to
    /// carry it, and neither on its own is enough.
    fn routes_ipv6(&self) -> bool {
        self.wants_v6.load(Ordering::Relaxed) && self.ipv6_support() == Ipv6Support::Carries
    }

    /// What DNS has learned, for the resolver that fills it and the packet path that renews it.
    pub fn leases(&self) -> &Arc<Leases> {
        &self.leases
    }

    /// What is routed into the tunnel right now.
    pub fn routes(&self) -> BTreeSet<Prefix> {
        self.locked_routes().installed().clone()
    }

    /// Everything that should be routed: what was asked for, plus a host route per leased address.
    ///
    /// Serialised by the routing lock, so two callers changing different halves at the same moment
    /// end with the table agreeing with both rather than with a mixture of the two.
    fn install_union(&self) -> Result<Change, TunError> {
        let mut routes = self.locked_routes();
        let carries_v6 = self.routes_ipv6();
        let mut wanted = self.locked_asked().clone();
        for address in self.leases.addresses() {
            wanted.insert((address, if address.is_ipv4() { 32 } else { 128 }));
        }
        // Whatever the two halves asked for, a v6 prefix goes in only if the tunnel was measured
        // carrying v6 and the application asked for it. A name that resolved to an AAAA is still
        // answered with that AAAA — it simply goes out over the line, which is where it went
        // before any of this existed.
        wanted.retain(|(address, _)| carries_v6 || address.is_ipv4());

        let change = routes.apply(&self.adapter, &wanted)?;
        if !change.is_empty() {
            notice!(
                "route",
                "+{} -{}, {} prefixes now",
                change.added.len(),
                change.removed.len(),
                routes.installed().len()
            );
            // The prefixes themselves, and for a leased one the names that produced it: on this
            // level the question is no longer "did routing change" but "why is that address here".
            for (address, prefix) in &change.added {
                let names = self.leases.names_for(*address);
                match names.is_empty() {
                    true => debug!("route", "+ {address}/{prefix}"),
                    false => debug!("route", "+ {address}/{prefix} ({})", names.join(", ")),
                }
            }
            for (address, prefix) in &change.removed {
                debug!("route", "- {address}/{prefix}");
            }
        }
        Ok(change)
    }

    /// Throw away the tunnel that is up and open a fresh one.
    ///
    /// There are two reasons this exists. The first is that the caller sometimes knows before the
    /// core does: the machine has just woken, or the network has just changed, and waiting for the
    /// endpoint to fall silent wastes the seconds the caller could have saved. The second is that
    /// it makes the claim this design rests on checkable on demand — that replacing a tunnel
    /// moves neither the adapter nor a single route.
    pub fn reconnect(&self) {
        self.reconnects.send_modify(|asked| *asked += 1);
    }

    /// Resolves when a reconnect is asked for after this was called.
    ///
    /// Subscribing marks the current count as seen, so this waits for the next request rather than
    /// returning immediately because of one served long ago.
    pub async fn reconnect_asked(&self) {
        let mut asked = self.reconnects.subscribe();
        let _ = asked.changed().await;
    }

    /// Say that the line under the tunnel changed.
    ///
    /// Deliberately not a reconnect. A tunnel riding an interface that did not move is still a
    /// working tunnel, and throwing it away because some other adapter appeared would spend a
    /// handshake on nothing. What this asks for is the *question* to be put now — is the endpoint
    /// still answering — instead of at the end of the current interval. If it is, nothing happens
    /// at all; if it is not, the failure is found in a fraction of a second rather than in five.
    ///
    /// Called from a callback the operating system runs on a thread of its own, so it does nothing
    /// but this: which interface and how, in two atomics, and one counter — no lock held across
    /// anything, and nothing written to the journal from that thread.
    pub fn line_changed(&self, interface: u64, kind: i32) {
        self.last_change_interface
            .store(interface, Ordering::Relaxed);
        self.last_change_kind.store(kind, Ordering::Relaxed);
        self.line.send_modify(|seen| *seen += 1);
    }

    /// Resolves when the line changes after this was called, and says at `debug` what changed.
    ///
    /// Said here, where it is acted on, rather than where Windows reports it: the report arrives on
    /// the operating system's thread, and naming the interface is a call back into IP Helper.
    /// Changes arrive in bursts, so the one named is the latest of the burst that woke this.
    pub async fn line_change(&self) {
        let mut changed = self.line.subscribe();
        let _ = changed.changed().await;
        debug!(
            "link",
            "{}",
            crate::link::describe(
                self.last_change_interface.load(Ordering::Relaxed),
                self.last_change_kind.load(Ordering::Relaxed)
            )
        );
    }

    /// Ask the core to stop. Whoever is running it is waiting on [`Core::stopped`].
    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    /// Resolves when someone has asked the core to stop.
    ///
    /// A latch rather than a notification: `wait_for` reads the current value before it waits, so
    /// a stop that arrived before anyone was listening still counts. A notification sent into an
    /// empty room would simply have been lost.
    pub async fn stopped(&self) {
        let mut asked = self.stop.subscribe();
        let _ = asked.wait_for(|&asked| asked).await;
    }

    /// A panic while the route set was being changed would poison the lock, and the set would still
    /// describe what is really installed — `apply` only records what it has already done. Refusing
    /// to touch routing after that would be worse than carrying on.
    fn locked_routes(&self) -> std::sync::MutexGuard<'_, Routes> {
        self.routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn locked_asked(&self) -> std::sync::MutexGuard<'_, BTreeSet<Prefix>> {
        self.asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A lookup table only; a panic cannot leave an entry half-written.
    fn locked_line_sources(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, LineSource>> {
        self.line_sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The DNS side learns addresses and says so; this is where saying so becomes routing.
///
/// Deliberately swallowing the outcome. A route that could not be installed is a failure of one
/// address, and there is nothing useful for a resolver in the middle of answering a query to do
/// about it — the next change re-derives the whole set from scratch, so nothing stays wrong for
/// longer than one edit.
impl RouteSink for Core {
    /// How many prefixes went in. A failure is reported as none rather than raised: the resolver
    /// has already answered by the time this is called, and the routing table saying no is not a
    /// reason to withhold an answer that is correct.
    ///
    /// A prefix the application asked for in the same moment would be counted here, because the
    /// union is installed in one step and the step does not record which half asked. The window is
    /// the width of one routing lock, and separating the two would be a great deal of bookkeeping
    /// for a counter.
    fn routes_changed(&self) -> usize {
        self.refresh_routes()
            .map(|change| change.added.len())
            .unwrap_or(0)
    }

    /// Looked up once per destination and line, and again after [`LINE_SOURCE_TTL`]: the lookup
    /// walks a routing table this core alone fills with hundreds of rows, and it is asked on every
    /// query a direct resolver answers.
    ///
    /// The walk is done without the lock held, so a slow one does not hold up queries for other
    /// resolvers; two queries racing on an expired entry both look it up, which costs a walk.
    fn line_source(&self, destination: IpAddr) -> Option<IpAddr> {
        let line = *self.line.borrow();
        let now = Instant::now();
        let known = self.locked_line_sources().get(&destination).copied();
        if let Some(known) = known
            && known.line == line
            && now.duration_since(known.at) < LINE_SOURCE_TTL
        {
            return known.from;
        }

        let from = crate::tun::outside::source_for(self.adapter.luid(), destination);
        if known.map(|known| known.from) != Some(from) {
            match from {
                Some(from) => info!("dns", "{destination} is asked from {from}, off the tunnel"),
                None => debug!(
                    "dns",
                    "no route to {destination} outside the tunnel; asked as the routing table sends it"
                ),
            }
        }
        self.locked_line_sources().insert(
            destination,
            LineSource {
                line,
                at: now,
                from,
            },
        );
        from
    }
}
