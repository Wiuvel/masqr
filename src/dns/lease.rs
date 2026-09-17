//! How long an address stays routed because a name resolved to it.
//!
//! Not a cache of answers — Windows already has one, and a second would give the machine two
//! opinions about the same name. What is kept is the other half: which addresses were handed out
//! and how long they may be believed, since those are what the routing table is made of.
//!
//! Taking a route from a connection that is using it does not slow that connection down, it kills
//! it: the next packet leaves by another interface with another source address. Two rules follow.
//!
//!   * A lease lasts at least [`MIN_LEASE`], however short the record's time to live.
//!   * A lease is renewed by use, not only by another answer.
//!
//! So an address carrying traffic is never unrouted, and an address nobody has used since its
//! record expired does not stay pinned for the rest of the session.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::message::Record;

/// The shortest a lease may be.
///
/// A content network hands out records that live thirty seconds. That is how long its answer is
/// worth trusting, not how long a download takes; routing on the number directly would take the
/// route out from under a connection a minute after it opened.
pub const MIN_LEASE: Duration = Duration::from_secs(600);

/// The longest a lease may be, whatever a record claims.
///
/// A day-long time to live is a statement about a name, not a licence to pin an address for a day.
/// The ceiling is what makes a set of routes that drifts away from what the names now mean
/// impossible rather than merely unlikely.
pub const MAX_LEASE: Duration = Duration::from_secs(3600);

/// How many addresses may be held at once.
///
/// A bound rather than a guess: without one, a stream of answers naming fresh addresses grows the
/// routing table of the machine without limit, and nothing in the protocol stops one.
pub const MAX_LEASES: usize = 8192;

/// One address, and why it is held.
#[derive(Debug)]
struct Lease {
    /// Milliseconds from the table's own start. Atomic so renewing by use needs only a shared
    /// borrow, keeping the packet path off the write lock.
    expires_ms: AtomicU64,
    /// The names that produced this address. More than one is ordinary — two names on one content
    /// network share addresses constantly — and it is why a lease cannot be dropped just because
    /// one of its names expired.
    names: BTreeSet<String>,
}

/// The addresses the tunnel carries on account of DNS, and their expiry.
#[derive(Debug)]
pub struct Leases {
    /// Everything is measured from here, so an expiry is a `u64` that can live in an atomic.
    base: Instant,
    held: RwLock<HashMap<IpAddr, Lease>>,
}

impl Default for Leases {
    fn default() -> Self {
        Self::new()
    }
}

impl Leases {
    /// An empty table, with the clock it measures every lease against started here.
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            held: RwLock::new(HashMap::new()),
        }
    }

    /// When the table started, so a caller can express a moment in the same terms the tests do.
    pub fn base(&self) -> Instant {
        self.base
    }

    /// Take in what an answer said.
    ///
    /// Returns `true` only when the set of held addresses changed, since that is the only reason to
    /// touch the routing table. An answer repeating addresses already held renews them and changes
    /// nothing, which is the common case by a wide margin.
    pub fn record(&self, name: &str, records: &[Record], now: Instant) -> bool {
        if records.is_empty() {
            return false;
        }
        let now_ms = self.millis(now);
        let mut held = self.write();
        let mut changed = false;

        for record in records {
            let expires_ms = now_ms + Self::lifetime(record.ttl).as_millis() as u64;
            match held.get_mut(&record.address) {
                Some(lease) => {
                    // Never shortened. Two names can hold one address with different times to live,
                    // and the address is needed until the last of them stops needing it.
                    lease.expires_ms.fetch_max(expires_ms, Ordering::Relaxed);
                    lease.names.insert(name.to_owned());
                }
                None => {
                    if held.len() >= MAX_LEASES {
                        Self::evict_one(&mut held);
                    }
                    held.insert(
                        record.address,
                        Lease {
                            expires_ms: AtomicU64::new(expires_ms),
                            names: BTreeSet::from([name.to_owned()]),
                        },
                    );
                    changed = true;
                }
            }
        }
        changed
    }

    /// Renew the lease on an address that is carrying traffic.
    ///
    /// Called from the packet path, so it takes a shared borrow and writes one integer. An address
    /// nothing has sent to in [`MIN_LEASE`] is one whose expiry is allowed to arrive.
    pub fn touch(&self, address: IpAddr, now: Instant) {
        let held = self.read();
        if let Some(lease) = held.get(&address) {
            let floor = self.millis(now) + MIN_LEASE.as_millis() as u64;
            lease.expires_ms.fetch_max(floor, Ordering::Relaxed);
        }
    }

    /// Let go of everything whose time has passed. Returns `true` when anything was let go.
    pub fn expire(&self, now: Instant) -> bool {
        let now_ms = self.millis(now);
        let mut held = self.write();
        let before = held.len();
        held.retain(|_, lease| lease.expires_ms.load(Ordering::Relaxed) > now_ms);
        held.len() != before
    }

    /// Every address held right now.
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.read().keys().copied().collect()
    }

    /// Why an address is held, for a log line that has to say more than "it is".
    pub fn names_for(&self, address: IpAddr) -> Vec<String> {
        self.read()
            .get(&address)
            .map(|lease| lease.names.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// How many addresses are held. This is the number of host routes the leases contribute.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether any address is held at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A record's time to live, brought inside the bounds a route can live with.
    fn lifetime(ttl: u32) -> Duration {
        Duration::from_secs(u64::from(ttl)).clamp(MIN_LEASE, MAX_LEASE)
    }

    fn millis(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.base).as_millis() as u64
    }

    /// Make room by dropping the lease that expires soonest.
    ///
    /// Dropping the soonest rather than the oldest is the difference between losing the address
    /// least likely to still be wanted and losing one that traffic has been renewing all along.
    fn evict_one(held: &mut HashMap<IpAddr, Lease>) {
        let victim = held
            .iter()
            .min_by_key(|(_, lease)| lease.expires_ms.load(Ordering::Relaxed))
            .map(|(address, _)| *address);
        if let Some(address) = victim {
            held.remove(&address);
        }
    }

    /// A poisoned lock means a panic while the table was being changed. The table is still a set of
    /// addresses and expiries — nothing half-written can survive one operation — and refusing to
    /// route anything ever again would be a worse answer than carrying on.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<IpAddr, Lease>> {
        self.held
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<IpAddr, Lease>> {
        self.held
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(address: &str, ttl: u32) -> Record {
        Record {
            name: "edge.example.com".into(),
            address: address.parse().unwrap(),
            ttl,
        }
    }

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn an_answer_makes_its_addresses_held() {
        let leases = Leases::new();
        let now = leases.base();
        assert!(leases.record("a.test", &[record("1.2.3.4", 300)], now));

        let mut held = leases.addresses();
        held.sort();
        assert_eq!(held, vec![address("1.2.3.4")]);
        assert_eq!(leases.names_for(address("1.2.3.4")), vec!["a.test"]);
    }

    /// The common case: the same answer again. Nothing changed, so nothing should be reported as
    /// changed — the caller uses that to decide whether to touch the routing table at all.
    #[test]
    fn repeating_an_answer_renews_without_changing_the_set() {
        let leases = Leases::new();
        let now = leases.base();
        assert!(leases.record("a.test", &[record("1.2.3.4", 300)], now));
        assert!(!leases.record("a.test", &[record("1.2.3.4", 300)], now));
        assert_eq!(leases.len(), 1);
    }

    /// A record's own time to live is about the answer, not about the connection using it. Below
    /// the floor it would take the route away from a download that is still running.
    #[test]
    fn a_short_time_to_live_is_lifted_to_the_floor() {
        let leases = Leases::new();
        let now = leases.base();
        leases.record("a.test", &[record("1.2.3.4", 30)], now);

        assert!(!leases.expire(now + MIN_LEASE - Duration::from_secs(1)));
        assert!(leases.expire(now + MIN_LEASE + Duration::from_secs(1)));
        assert!(leases.is_empty());
    }

    #[test]
    fn a_long_time_to_live_is_brought_down_to_the_ceiling() {
        let leases = Leases::new();
        let now = leases.base();
        leases.record("a.test", &[record("1.2.3.4", 86_400)], now);
        assert!(leases.expire(now + MAX_LEASE + Duration::from_secs(1)));
    }

    /// The guarantee the packet path buys: an address that traffic keeps using is never unrouted,
    /// however long ago the name that produced it was resolved.
    #[test]
    fn an_address_in_use_outlives_its_record() {
        let leases = Leases::new();
        let now = leases.base();
        leases.record("a.test", &[record("1.2.3.4", 30)], now);

        // Well past the point the record alone would have expired.
        let later = now + MAX_LEASE * 2;
        leases.touch(address("1.2.3.4"), later);
        assert!(!leases.expire(later + Duration::from_secs(1)));
        assert_eq!(leases.len(), 1);

        // And once nothing uses it, the floor since the last use is all it gets.
        assert!(leases.expire(later + MIN_LEASE + Duration::from_secs(1)));
    }

    /// Touching an address nobody leased must not create one. Traffic to an address the tunnel
    /// carries for another reason is not a reason to hold it on the DNS side.
    #[test]
    fn touching_an_address_that_is_not_held_holds_nothing() {
        let leases = Leases::new();
        leases.touch(address("9.9.9.9"), leases.base());
        assert!(leases.is_empty());
    }

    /// Content networks hand the same addresses to different names all day. The address has to
    /// survive the expiry of either name on its own.
    #[test]
    fn an_address_shared_by_two_names_lives_as_long_as_the_longer_of_them() {
        let leases = Leases::new();
        let now = leases.base();
        leases.record("a.test", &[record("1.2.3.4", 30)], now);
        leases.record("b.test", &[record("1.2.3.4", 3600)], now);

        assert_eq!(
            leases.names_for(address("1.2.3.4")),
            vec!["a.test", "b.test"]
        );
        assert!(!leases.expire(now + MIN_LEASE + Duration::from_secs(1)));
        assert!(leases.expire(now + MAX_LEASE + Duration::from_secs(1)));
    }

    /// A later answer may only ever push an expiry further out. Shortening one would let a name
    /// with a brief record take the route away from traffic another name is still using.
    #[test]
    fn a_later_answer_never_shortens_a_lease() {
        let leases = Leases::new();
        let now = leases.base();
        leases.record("a.test", &[record("1.2.3.4", 3600)], now);
        leases.record("a.test", &[record("1.2.3.4", 30)], now);
        assert!(!leases.expire(now + MIN_LEASE + Duration::from_secs(1)));
    }

    /// The table is bounded, and the bound is reached by dropping what expires soonest rather than
    /// by refusing to hold anything new.
    #[test]
    fn the_table_stays_within_its_bound() {
        let leases = Leases::new();
        let now = leases.base();
        // The first address is given the longest life, so it is the one that must survive.
        leases.record("keep.test", &[record("10.0.0.1", 86_400)], now);
        for n in 0..MAX_LEASES + 16 {
            let address = format!("172.{}.{}.{}", (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
            leases.record("churn.test", &[record(&address, 60)], now);
        }
        assert!(leases.len() <= MAX_LEASES);
        assert!(
            leases.names_for(address("10.0.0.1")).len() == 1,
            "the longest-lived lease is not the one evicted"
        );
    }

    #[test]
    fn an_answer_with_no_addresses_changes_nothing() {
        let leases = Leases::new();
        assert!(!leases.record("a.test", &[], leases.base()));
    }
}
