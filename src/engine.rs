//! Keeping the tunnel up, and pumping packets across it.
//!
//! Two facts live here that the layers below do not know: that a tunnel can die and be replaced,
//! and that the two directions must not wait for each other.
//!
//! Replacement is cheap because of where the routes point — at the adapter, not at the connection.
//! A reconnect opens a new CONNECT-IP stream and swaps the two halves of the pump; the adapter, its
//! address and the whole route set stay as they were. Nothing in the system's network state moves
//! when the tunnel does.

use std::convert::Infallible;
use std::time::{Duration, Instant};

use crate::queue::PacketQueue;

use crate::core::{Core, PathReading, Phase};
use crate::probe;
use crate::transport::carrier::{self, Carrier, Plan};
use crate::transport::{self, ConnectError, Stages, Tunnel};
use crate::tun::Writer;
use crate::warp::{Enrolment, Identity, refusal_is_about_the_device};

/// How long to wait before each retry, by the number of failures already seen in a row.
///
/// The first entry is short on purpose: a tunnel that was up a moment ago has usually lost
/// something momentary, and making the user wait out a long backoff for that is the common case
/// being punished for the rare one. The last entry repeats for as long as it takes.
pub const BACKOFF: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(15),
];

/// How often the endpoint is asked whether it is still there, and how long an answer is waited for.
///
/// Together these two set the worst case for noticing a tunnel that has stopped working without
/// saying so: ten seconds. Measured against a link taken away on purpose, the old pair of fifteen
/// and ten took twenty-four, which is a long time to sit looking at a page that will not load.
///
/// The asymmetry is what makes being this eager safe. Reconnecting costs a fraction of a second and
/// touches neither the adapter nor a single route, so a false alarm on a congested line is almost
/// free — while a real failure gone unnoticed costs the person everything they were doing. A ping
/// frame every five seconds is a few bytes a second next to the traffic it protects.
const PING_EVERY: Duration = Duration::from_secs(5);
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the line is given to settle before the endpoint is asked about it.
///
/// Interface changes arrive in bursts — one adapter coming up produces several — and a question
/// put in the middle of one is answered by the burst rather than by the tunnel. Long enough to let
/// a burst finish, short enough that a link that really went away is still found in well under a
/// second.
const SETTLING: Duration = Duration::from_millis(300);

/// How long one attempt to open a tunnel may take before it is abandoned for a fresh one.
///
/// Without this an attempt made while the link is gone waits out the operating system's own
/// connect timeout, and the backoff schedule stops meaning anything: the engine would be stuck in
/// a single attempt for far longer than the schedule says it ever waits.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// What a tunnel killed on volume looks like: it opened, carried a little, and stopped answering.
///
/// Measured on a filtered link, a flow classified by its name is cut at 19.2 KiB. The ceiling here
/// is more than ten times that, so an ordinary session cannot be mistaken for one; the window is
/// short because the kill follows the traffic rather than the clock.
///
/// One of these is not evidence — a link can go away at any moment, including just after a tunnel
/// came up. A run of them is: a limit enforced on volume produces the same short life every time,
/// which nothing else does.
const CUT_SHORT_BYTES: u64 = 256 * 1024;
const CUT_SHORT_WITHIN: Duration = Duration::from_secs(60);
const CUT_SHORT_RUN: usize = 3;

/// Whether a tunnel's life looks like a limit being enforced rather than a link going away.
fn cut_short_life(lived: Duration, carried: u64) -> bool {
    lived < CUT_SHORT_WITHIN && carried < CUT_SHORT_BYTES
}

/// How many packets are taken from the queue and written as one run.
///
/// The ceiling is framing, not memory: at one MTU each this is about 40 KiB, and the endpoint's
/// frame size decides how it is cut up on the way out. Large enough that a busy tunnel stops
/// paying a system call per packet, small enough that the first packet of a run never waits on
/// the thirty-second.
const BATCH: usize = 32;

/// How often a tunnel over HTTP/2 looks at whether HTTP/3 may be tried again.
///
/// Parking decides when it may; this only bounds how late that is noticed. A try that fails costs
/// nothing the person sees — the HTTP/2 tunnel carries throughout — and parks HTTP/3 again.
const UPGRADE_EVERY: Duration = Duration::from_secs(30);

/// Why the pump stopped.
enum Stopped {
    /// Something failed, or someone asked; the sentence says which.
    Failed(String),
    /// HTTP/3 opened beside the HTTP/2 tunnel that was carrying, and is to carry from here on.
    Upgraded(Box<(Tunnel, Stages)>),
}

/// Carry packets for as long as the caller keeps this running.
///
/// Never returns: every failure is a reason to open another tunnel, not a reason to stop. Stopping
/// is the caller's decision, made by dropping this future — at which point the current tunnel and
/// everything under it goes with it.
pub async fn run(
    enrolment: &Enrolment,
    from_tun: &PacketQueue,
    to_tun: &Writer,
    core: &Core,
) -> Infallible {
    let mut failures = 0usize;
    // How many tunnels in a row died having carried almost nothing.
    let mut cut_short = 0usize;
    // A tunnel already open when the one before it stopped: HTTP/3, opened while HTTP/2 carried.
    let mut handed: Option<Box<(Tunnel, Stages)>> = None;
    let mut endpoint_line = EndpointLine::new(core, &enrolment.current());
    loop {
        let identity = enrolment.current();
        let upgraded = handed.is_some();
        let opening = match handed.take() {
            Some(opened) => Ok(Ok(*opened)),
            None => {
                core.phase.send_replace(Phase::Connecting {
                    attempt: failures + 1,
                });
                tokio::time::timeout(CONNECT_TIMEOUT, transport::connect(&identity)).await
            }
        };
        // Set alongside the reason: a handshake cut with no reply is the one failure that says
        // the fix is not here, and a supervisor has to be able to tell it apart without parsing.
        let mut blocked = false;
        let reason = match opening {
            Ok(Ok((mut tunnel, stages))) => {
                // Reset before the pump, not after: what matters for the next backoff is whether a
                // tunnel came up at all, and it did.
                failures = 0;
                core.phase.send_replace(Phase::Up { stages });
                let opened = Instant::now();
                let carried_before = core.counters.back.read().1;

                // Asked before the pump starts and while the tunnel is still whole, because the
                // question needs both directions of it and the pump takes them apart.
                if core.should_probe_ipv6()
                    && let Ok(inside) = identity.assigned_v6.parse()
                {
                    core.set_carries_ipv6(probe::carries_ipv6(&mut tunnel, inside).await);
                }

                // Whatever waited out the gap before this tunnel has been sent again by now, by
                // the connections that sent it.
                let stale = from_tun.drop_stale();
                if stale > 0 {
                    debug!(
                        "queue",
                        "{stale} packet(s) waited longer for a tunnel than their senders wait, and were dropped"
                    );
                }

                let why = pump(
                    tunnel,
                    stages.carrier(),
                    &identity,
                    &mut endpoint_line,
                    from_tun,
                    to_tun,
                    core,
                )
                .await;
                core.set_path(None);

                let why = match why {
                    Stopped::Upgraded(next) => {
                        notice!(
                            "tunnel",
                            "HTTP/3 opened beside the HTTP/2 tunnel; carrying over it from here on"
                        );
                        handed = Some(next);
                        continue;
                    }
                    Stopped::Failed(why) => why,
                };

                let lived = opened.elapsed();
                let carried = core.counters.back.read().1.saturating_sub(carried_before);
                if cut_short_life(lived, carried) {
                    cut_short += 1;
                    // The same run that is evidence of a limit is the reason to step down from
                    // HTTP/3: a limit enforced on the flow would cut every HTTP/3 tunnel the same
                    // way, and HTTP/2 is there to carry while HTTP/3 is parked. One short life is
                    // not enough — a reconnect asked for on an idle tunnel looks like one — unless
                    // HTTP/2 was carrying a moment before: then the line is not what went away.
                    let evidence = cut_short >= CUT_SHORT_RUN || upgraded;
                    if evidence && stages.carrier() == Carrier::H3 {
                        carrier::park(Instant::now());
                    }
                    if cut_short >= CUT_SHORT_RUN {
                        notice!(
                            "tunnel",
                            "{cut_short} tunnels in a row died after carrying under {} KiB — a link \
                             that classifies this flow and enforces a limit on it looks like this. \
                             The bypass underneath is what stops the flow being classified; \
                             `masqr handshake` measures which ClientHello this link lets carry.",
                            CUT_SHORT_BYTES / 1024
                        );
                    }
                } else {
                    cut_short = 0;
                }
                why
            }
            Ok(Err(problem)) => {
                if let ConnectError::Refused(status) = &problem
                    && refusal_is_about_the_device(*status)
                {
                    replace_device(enrolment, core, *status).await;
                }
                blocked = problem.is_blocked();
                problem.to_string()
            }
            Err(_) => format!(
                "the tunnel did not open within {} s",
                CONNECT_TIMEOUT.as_secs()
            ),
        };

        let retry_in = BACKOFF[failures.min(BACKOFF.len() - 1)];
        failures += 1;
        core.phase.send_replace(Phase::Lost {
            reason,
            retry_in,
            blocked,
        });
        // Someone asking for a reconnect while this waits knows something the loop does not: the
        // machine has woken, or the link has come back. Sitting out the rest of a backoff would
        // spend exactly the seconds they were trying to save, so the wait ends with the request.
        tokio::select! {
            _ = tokio::time::sleep(retry_in) => {}
            _ = core.reconnect_asked() => carrier::unpark(),
            // The line coming back is the same knowledge arriving from the operating system
            // instead of from a person, and it is the case the schedule punishes hardest: a
            // machine that woke into a working network sitting out fifteen seconds of a wait that
            // was measured for a network still broken. A line that moved may carry what the old
            // one would not, so HTTP/3 gets another try too — see `EndpointLine`.
            _ = core.line_change() => {
                if endpoint_line.moved() {
                    carrier::unpark();
                }
            }
        }
    }
}

/// Move packets both ways until something stops, and say what and why.
///
/// The directions are separate futures rather than arms of one loop, so that neither waits on the
/// other. A single loop would stall every arriving packet behind a send that is waiting for the
/// endpoint to open its flow-control window — which is exactly what a busy upload does to a
/// download.
///
/// The third future is not traffic at all. It asks, on a timer, whether the endpoint is still
/// answering, because the failure that matters most here is the one that never reports itself: a
/// connection left hanging by a link that went away, which neither closes nor carries anything.
/// The fourth is someone deciding the same thing from outside and saying so.
///
/// The fifth runs only on a tunnel over HTTP/2 that the run would rather have over HTTP/3. When
/// HTTP/3 may be tried again it is opened beside this tunnel, which carries meanwhile, and the pump
/// hands it over. The swap moves nothing the connections inside can see: the routes point at the
/// adapter, and the endpoint gives the same device the same addresses over either carrier.
async fn pump(
    tunnel: Tunnel,
    carrying: Carrier,
    identity: &Identity,
    endpoint_line: &mut EndpointLine,
    from_tun: &PacketQueue,
    to_tun: &Writer,
    core: &Core,
) -> Stopped {
    let (mut sender, mut receiver, mut health) = tunnel.split();
    // What QUIC had counted when the pump started, so the readings describe this tunnel's traffic
    // and not the exchange that opened it.
    let baseline = health
        .link_stats()
        .map(|stats| (stats.datagrams_in, core.counters.back.read().0));

    let outward = async {
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(BATCH);
        while from_tun.pop_batch(&mut batch, BATCH).await {
            let now = std::time::Instant::now();
            for packet in &batch {
                core.counters.out.record(packet.len());
                // An address carrying traffic must not have its route expire underneath it: the
                // next packet would leave by another interface with another source address, and
                // the connection would be dead. One hash lookup and one clock read per packet.
                if let Some(destination) = destination(packet) {
                    core.leases().touch(destination, now);
                }
            }
            sender
                .send(&mut batch)
                .await
                .map_err(|e| format!("sending into the tunnel: {e}"))?;
        }
        // The thread reading the adapter has ended, which is a different kind of failure from
        // every other one here: another tunnel would be opened to carry packets that nothing is
        // delivering any more. Reconnecting cannot reach it, so the core is asked to stop and
        // whatever supervises it starts a fresh one — with a fresh adapter, which is the part that
        // actually has to be replaced.
        core.stop();
        Err::<Infallible, String>("the adapter stopped delivering packets".to_string())
    };

    let inward = async {
        loop {
            let packet = receiver
                .recv()
                .await
                .map_err(|e| format!("reading from the tunnel: {e}"))?;
            let Some(packet) = packet else {
                return Err::<Infallible, String>("the endpoint closed the tunnel".to_string());
            };
            core.counters.back.record(packet.len());
            to_tun
                .send(&packet)
                .map_err(|e| format!("writing to the adapter: {e}"))?;
        }
    };

    let answering = async {
        loop {
            // Either the interval came round, or the line under the tunnel moved and there is no
            // reason to sit out the rest of it — a connection left hanging by an interface that
            // went away neither closes nor carries anything, and this is the moment it becomes
            // findable. A settling pause after a change, because changes arrive in bursts and a
            // question put in the middle of one measures the burst.
            tokio::select! {
                _ = tokio::time::sleep(PING_EVERY) => {}
                _ = core.line_change() => {
                    if endpoint_line.moved() {
                        carrier::unpark();
                    }
                    tokio::time::sleep(SETTLING).await;
                }
            }
            match tokio::time::timeout(PING_TIMEOUT, health.probe()).await {
                // The answer carries a round trip on the tunnel itself, and it is what the queue in
                // front of the tunnel works its delay target to — a measurement of this link rather
                // than a constant chosen against somebody else's.
                Ok(Ok(round_trip)) => {
                    from_tun.observe_rtt(round_trip);
                    if let (Some((datagrams, read)), Some(stats)) = (baseline, health.link_stats())
                    {
                        core.set_path(Some(PathReading {
                            rtt: stats.rtt,
                            cwnd: stats.cwnd,
                            sent: stats.sent,
                            lost: stats.lost,
                            datagrams: stats.datagrams_in.saturating_sub(datagrams),
                            read: core.counters.back.read().0.saturating_sub(read),
                        }));
                    }
                }
                Ok(Err(problem)) => {
                    return Err::<Infallible, String>(format!(
                        "the endpoint stopped answering: {problem}"
                    ));
                }
                Err(_) => {
                    return Err::<Infallible, String>(format!(
                        "the endpoint did not answer within {} s",
                        PING_TIMEOUT.as_secs()
                    ));
                }
            }
        }
    };

    let asked = async {
        core.reconnect_asked().await;
        carrier::unpark();
        Err::<Infallible, String>("a reconnect was asked for".to_string())
    };

    let upgrading = async {
        if carrying != Carrier::H2 {
            return std::future::pending().await;
        }
        loop {
            tokio::time::sleep(UPGRADE_EVERY).await;
            if !http3_would_be_tried(Instant::now()) {
                continue;
            }
            let problem = match tokio::time::timeout(
                CONNECT_TIMEOUT,
                transport::connect_h3(identity),
            )
            .await
            {
                Ok(Ok(opened)) => return Box::new(opened),
                Ok(Err(problem)) => problem.to_string(),
                Err(_) => format!("it did not open within {} s", CONNECT_TIMEOUT.as_secs()),
            };
            carrier::park(Instant::now());
            info!(
                "tunnel",
                "HTTP/3 still does not open ({problem}); HTTP/2 carries on, and HTTP/3 is tried \
                 again in {} min",
                carrier::PARK_FOR.as_secs() / 60
            );
        }
    };

    // All five are polled concurrently; whichever stops first ends the pump, and the rest are
    // dropped with it — the HTTP/2 tunnel included, once HTTP/3 has taken over.
    tokio::select! {
        stopped = outward => Stopped::Failed(stopped.unwrap_err()),
        stopped = inward => Stopped::Failed(stopped.unwrap_err()),
        stopped = answering => Stopped::Failed(stopped.unwrap_err()),
        stopped = asked => Stopped::Failed(stopped.unwrap_err()),
        opened = upgrading => Stopped::Upgraded(opened),
    }
}

/// Where this machine reaches the HTTP/3 endpoint from, and whether that has moved.
///
/// A line change is any notification about an interface that is not this core's, and a Wi-Fi
/// adapter sends them every five to fifteen seconds while nothing about the path moves — measured
/// over a quarter of an hour, every one from the adapter the path runs over. Unparking HTTP/3 on each
/// would make parking last seconds on a link that drops QUIC, and cost that link HTTP/3's timeouts
/// on every attempt again. What says the line HTTP/3 was refused on is no longer the one in use is
/// the source address the route to the endpoint gives, so that is what is compared: an adapter
/// going away, a new network, a new address.
struct EndpointLine {
    ours: u64,
    endpoint: Option<std::net::IpAddr>,
    from: Option<std::net::IpAddr>,
}

impl EndpointLine {
    fn new(core: &Core, identity: &Identity) -> Self {
        let ours = core.adapter().luid();
        let endpoint = identity.endpoint_h3_v4().parse().ok();
        Self {
            ours,
            endpoint,
            from: endpoint.and_then(|to| crate::tun::outside::source_for(ours, to)),
        }
    }

    /// Look the source address up again, and say whether it differs from the last one seen.
    fn moved(&mut self) -> bool {
        let Some(endpoint) = self.endpoint else {
            return true;
        };
        source_moved(
            &mut self.from,
            crate::tun::outside::source_for(self.ours, endpoint),
        )
    }
}

/// Record `now` as the source address, and say whether it differs from what was recorded.
fn source_moved(seen: &mut Option<std::net::IpAddr>, now: Option<std::net::IpAddr>) -> bool {
    let moved = *seen != now;
    *seen = now;
    moved
}

/// Whether an attempt made now would start with HTTP/3: the run chose `auto`, the handshake is one
/// QUIC can carry, and HTTP/3 is not parked.
fn http3_would_be_tried(now: Instant) -> bool {
    carrier::plan(
        carrier::selected(),
        transport::handshake::selected(),
        carrier::parked(now),
    ) == Plan::H3ThenH2
}

/// Where a packet is going, or `None` when it is not an IP packet this core understands.
fn destination(packet: &[u8]) -> Option<std::net::IpAddr> {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let octets: [u8; 4] = packet[16..20].try_into().ok()?;
            Some(std::net::IpAddr::from(octets))
        }
        Some(6) if packet.len() >= 40 => {
            let octets: [u8; 16] = packet[24..40].try_into().ok()?;
            Some(std::net::IpAddr::from(octets))
        }
        _ => None,
    }
}

/// The endpoint declined this device. Enrol another, and stop so the next start uses it.
///
/// It stops rather than carrying on. A fresh registration brings fresh addresses inside the
/// tunnel while the adapter still carries the old ones, and changing an interface's address under
/// a running core is a great deal of care for an event that happens almost never. The new device
/// is on disk before this returns, so restarting is all that is left, and the supervisor knows
/// how.
async fn replace_device(enrolment: &Enrolment, core: &Core, status: http::StatusCode) {
    match enrolment.refresh(std::time::Instant::now()).await {
        Ok(Ok(_)) => {
            notice!(
                "warp",
                "the endpoint refused this device ({status}); a new one is registered in {} — \
                 stopping so the next start uses it",
                enrolment.path().display()
            );
            core.stop();
        }
        Ok(Err(_)) => {
            // Refused again inside the interval. This refusal is about something else, and
            // registering a second device would answer none of it.
            warn!(
                "warp",
                "the endpoint refused this device ({status}), and one was registered too recently \
                 for that to be the reason"
            );
        }
        Err(problem) => {
            error!(
                "warp",
                "a replacement device could not be registered: {problem}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tunnel_killed_on_volume_is_told_from_one_that_worked() {
        // The measured kill point on a classified flow is 19.2 KiB, a few seconds in.
        assert!(cut_short_life(Duration::from_secs(11), 19 * 1024));
        // A session that carried real traffic is not it, however briefly it lasted.
        assert!(!cut_short_life(Duration::from_secs(11), 4 * 1024 * 1024));
        // Nor is one that lived, even if the machine had nothing to send through it.
        assert!(!cut_short_life(Duration::from_secs(600), 1024));
    }

    /// The destination sits at a different offset in each family, and reading the wrong one would
    /// renew the lease on an address nothing is talking to while letting the real one expire.
    #[test]
    fn a_packet_says_where_it_is_going() {
        let mut v4 = vec![0x45u8; 20];
        v4[16..20].copy_from_slice(&[104, 16, 0, 1]);
        assert_eq!(
            destination(&v4),
            Some("104.16.0.1".parse().expect("a literal address"))
        );

        let mut v6 = vec![0x60u8; 40];
        v6[24..40].copy_from_slice(&[0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            destination(&v6),
            Some("2606:4700::1".parse().expect("a literal address"))
        );
    }

    /// Parking is lifted when the address the endpoint is reached from moves, and only then: a
    /// parameter change on the same adapter, however often it arrives, is not a new line.
    #[test]
    fn only_a_moved_source_address_is_a_new_line() {
        let line: std::net::IpAddr = "192.168.1.64".parse().expect("a literal address");
        let other: std::net::IpAddr = "10.0.0.7".parse().expect("a literal address");
        let mut seen = Some(line);

        assert!(!source_moved(&mut seen, Some(line)));
        assert!(source_moved(&mut seen, None), "the adapter went away");
        assert!(source_moved(&mut seen, Some(line)), "and came back");
        assert!(source_moved(&mut seen, Some(other)), "a different network");
        assert!(!source_moved(&mut seen, Some(other)));
    }

    /// Anything too short to hold an address, or that is not an IP packet at all, renews nothing.
    #[test]
    fn something_that_is_not_a_packet_says_nothing() {
        assert_eq!(destination(&[]), None);
        assert_eq!(destination(&[0x45, 0x00]), None);
        assert_eq!(destination(&[0x60u8; 20]), None);
        assert_eq!(destination(&[0x25u8; 40]), None);
    }
}
