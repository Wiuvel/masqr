//! The resolver the machine talks to.
//!
//! A forwarder with an opinion about two things only: which upstream answers a name, and whether
//! the addresses in the answer become routes. Records, flags and order are passed through
//! untouched.
//!
//! It listens on UDP and TCP, because the protocol requires both and because the answers that need
//! TCP are the large ones content networks give.
//!
//! The one message this module writes is the failure reply, built by editing the query's own
//! header. A forwarder that cannot reach an upstream has to say so: dropping the query would leave
//! the machine waiting out its own timeouts with no other resolver to try.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use std::os::windows::io::AsRawSocket;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, Semaphore, oneshot};
use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, SOCKET, WSAIoctl};

use super::asker::Askers;
use super::asker::From;
use super::lease::Leases;
use super::message::{self, CLASS_IN, TYPE_A, TYPE_AAAA};
use super::policy::{Asker, Policy, PolicyInput, Via};
use super::upstream::Upstreams;

/// The most queries answered at once.
///
/// A bound rather than a task per datagram: a machine that floods its own resolver, or an
/// application in a retry loop, would otherwise turn a burst of queries into an unbounded number of
/// tasks each holding an upstream socket. Past the bound a query is dropped, which is what a busy
/// resolver does and what every client already knows how to survive.
const MAX_IN_FLIGHT: usize = 512;

/// The largest query accepted. A DNS message cannot exceed this, and reading further would be
/// reading something that is not one.
const MAX_MESSAGE: usize = 65_535;

/// Bytes of header every message has.
const HEADER_LEN: usize = 12;

/// How long a TCP client may hold a connection open with nothing on it.
const TCP_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// What the server has been asked to do, replaced whole.
///
/// The policy and the clients that serve it are swapped together and never separately: a policy
/// installed without its upstreams, even for an instant, would name resolvers that do not exist.
struct Installed {
    policy: Policy,
    upstreams: Upstreams,
}

/// Counters worth reporting, and nothing that is only interesting while debugging.
#[derive(Debug, Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub answered: AtomicU64,
    pub failed: AtomicU64,
    pub routed: AtomicU64,
}

/// What happens to an answer once it comes back.
///
/// A trait, because the thing that owns routing is above this module and has no business being
/// reached down into. The DNS side learns addresses; something else decides what a routing table
/// does about them.
pub trait RouteSink: Send + Sync {
    /// The set of leased addresses changed. Whatever owns the routing table should make it agree,
    /// and say how many routes that added — which is not the same number as the addresses handed
    /// over, and is the only side that knows the difference.
    fn routes_changed(&self) -> usize;

    /// The local address that reaches `destination` by the line rather than through the tunnel,
    /// for an upstream the policy says is asked directly. `None` when the line has no route to it,
    /// and the query then goes wherever the routing table sends it.
    fn line_source(&self, destination: IpAddr) -> Option<IpAddr>;
}

/// The resolver, its policy, and what it has learned.
pub struct Resolver {
    installed: RwLock<Option<Installed>>,
    leases: Arc<Leases>,
    sink: Arc<dyn RouteSink>,
    stats: Stats,
    /// Who is asking, when that can be established. Only ever used to let a rule about a program
    /// apply; nothing here routes by process, because a routing table cannot.
    askers: Askers,
    /// Shared rather than owned so a permit can outlive the borrow that took it, letting the bound
    /// hold while the query is answered on its own task.
    in_flight: Arc<Semaphore>,
    /// One name this resolver is watching for, and the way it says the name arrived.
    ///
    /// Set for a few seconds at a time, while something checks that the machine's names really do
    /// reach here. The flag is what keeps that off the ordinary path: a query costs one atomic
    /// load to find out that nothing is being watched for, and the lock is taken only in the
    /// window where something is.
    watching: std::sync::Mutex<Option<(String, oneshot::Sender<()>)>>,
    watched: std::sync::atomic::AtomicBool,
    /// Where this resolver answers, when it answers anywhere.
    ///
    /// Held for one purpose: refusing a policy that names this very address as an upstream. That is
    /// a resolver asking itself, and it does not fail — it times out, once per query, for as long
    /// as the policy stands. Measured on a real machine: every ordinary name took four seconds and
    /// then no answer, which from a browser is indistinguishable from having no DNS at all.
    listen: Option<SocketAddr>,
}

impl Resolver {
    /// A resolver with no policy yet.
    ///
    /// It exists before it listens and listens before a policy arrives, which is deliberate: the
    /// listener has to be up before the machine is pointed at it, and every query in the window
    /// between is answered with a refusal rather than dropped.
    pub fn new(leases: Arc<Leases>, sink: Arc<dyn RouteSink>, listen: Option<SocketAddr>) -> Self {
        Self {
            installed: RwLock::new(None),
            leases,
            sink,
            stats: Stats::default(),
            askers: Askers::new(),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            watching: std::sync::Mutex::new(None),
            watched: std::sync::atomic::AtomicBool::new(false),
            listen,
        }
    }

    /// Wait for one name to be asked of this resolver.
    ///
    /// The one thing that proves the machine's names arrive here is a name arriving here — asked
    /// of the operating system, by the path any program's names take. Nothing else distinguishes a
    /// resolver the machine uses from a socket that happens to be open.
    ///
    /// One at a time: the second watch replaces the first, whose receiver then reports that it
    /// will never fire, which is the truthful answer for a check that was superseded.
    pub fn watch_for(&self, name: &str) -> oneshot::Receiver<()> {
        let (tell, told) = oneshot::channel();
        *held(&self.watching) = Some((name.to_ascii_lowercase(), tell));
        self.watched.store(true, Ordering::Release);
        told
    }

    /// Where this resolver answers, when it answers anywhere.
    pub fn answers_at(&self) -> Option<SocketAddr> {
        self.listen
    }

    /// Stop watching, whether or not the name ever came.
    pub fn stop_watching(&self) {
        self.watched.store(false, Ordering::Release);
        *held(&self.watching) = None;
    }

    /// Whether this name is the one being watched for, and if so, say that it arrived.
    fn watching_for(&self, name: &str) -> bool {
        if !self.watched.load(Ordering::Acquire) {
            return false;
        }
        let mut watching = held(&self.watching);
        match watching.as_ref() {
            Some((wanted, _)) if wanted.eq_ignore_ascii_case(name) => {
                if let Some((_, tell)) = watching.take() {
                    let _ = tell.send(());
                }
                true
            }
            _ => false,
        }
    }

    /// Put a policy in place, replacing whatever was there.
    ///
    /// Everything that can be refused is refused here: a rule naming a resolver nobody declared, a
    /// DoH endpoint that is not a url, a policy that decides nothing about some names. Refusing at
    /// install leaves the previous policy running, which is a working machine; accepting a broken
    /// one would not be.
    pub async fn install(&self, input: PolicyInput) -> Result<InstallReport, InstallError> {
        let policy = Policy::build(input).map_err(InstallError::Policy)?;
        if !policy.decides_everything() {
            return Err(InstallError::NoCatchAll);
        }
        // A plain resolver at the address this core answers on is this core. The question would be
        // asked of itself, and the answer is not an error but a four-second silence per name.
        if let Some(listen) = self.listen
            && let Some(circular) = policy
                .resolvers()
                .find(|r| r.kind == crate::dns::policy::Kind::Plain && r.address == listen.ip())
        {
            return Err(InstallError::Circular(circular.id.clone()));
        }
        let upstreams = Upstreams::build(policy.resolvers()).map_err(InstallError::Upstream)?;

        let report = InstallReport {
            rules: policy.rule_count(),
            resolvers: policy.resolver_count(),
            tunnelled: policy.tunnelled_resolvers().count(),
        };
        notice!(
            "dns",
            "policy: {} rules over {} resolvers, {} of them through the tunnel",
            report.rules,
            report.resolvers,
            report.tunnelled
        );
        *self.installed.write().await = Some(Installed { policy, upstreams });
        // The resolvers reached through the tunnel have to be routed there before the first query
        // needs one, or that query goes out over the line and answers from the wrong side.
        self.sink.routes_changed();
        Ok(report)
    }

    /// What has been asked and answered, for whoever reports on the core.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// The addresses answers have put into routing.
    pub fn leases(&self) -> &Arc<Leases> {
        &self.leases
    }

    /// The addresses of every declared resolver that is reached through the tunnel.
    pub async fn tunnelled_resolvers(&self) -> Vec<std::net::IpAddr> {
        match self.installed.read().await.as_ref() {
            Some(installed) => installed.policy.tunnelled_resolvers().collect(),
            None => Vec::new(),
        }
    }

    /// Answer one query, or say why not.
    ///
    /// The reply is the upstream's own bytes. What this adds is the decision about where to ask and
    /// the bookkeeping about what came back.
    pub async fn answer(&self, query: &[u8], from: Option<From>) -> Option<Vec<u8>> {
        self.stats.queries.fetch_add(1, Ordering::Relaxed);

        let asked = match message::read_query(query) {
            Ok(asked) => asked,
            // Not a query this can read. There is nothing to forward and nothing to say about it.
            Err(problem) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                warn!("dns", "a query could not be read: {problem}");
                return failure_reply(query);
            }
        };

        // Before the policy, and answered without it: this name exists only to be seen arriving,
        // it is in the namespace reserved for names that resolve to nothing, and forwarding it
        // would put a question to an upstream that nobody wants the answer to.
        if self.watching_for(&asked.name) {
            info!("dns", "the machine's names arrive here");
            return failure_reply(query);
        }

        let started = Instant::now();
        // Looked up before the policy is consulted, because a rule may be about the program as well
        // as about the name. An unknown asker matches no such rule, which is the reading that
        // cannot apply a narrow rule to everything.
        let program = from.and_then(|from| self.askers.of_port(from, started));
        let asker = program.as_ref().map(|p| Asker {
            path: &p.path,
            name: &p.name,
        });

        let (outcome, route, resolver, rule) = {
            let guard = self.installed.read().await;
            // Every way out of this block is a reply. A query dropped instead leaves whoever asked
            // waiting out its own timeout with nowhere else to go, because this is the only
            // resolver the machine has — and the window with no policy in place is not
            // hypothetical: the listener is bound before the application has installed one.
            let Some(installed) = guard.as_ref() else {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "dns",
                    "{} {} arrived before a policy was installed",
                    type_name(asked.qtype),
                    asked.name
                );
                return failure_reply(query);
            };
            let Some(decision) = installed.policy.decide(&asked.name, asker) else {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                warn!("dns", "the policy decides nothing about {}", asked.name);
                return failure_reply(query);
            };
            let Some(upstream) = installed.upstreams.get(&decision.resolver.id) else {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                error!(
                    "dns",
                    "rule {} names the resolver `{}`, which was not prepared",
                    decision.rule,
                    decision.resolver.id
                );
                return failure_reply(query);
            };
            // Copied out before the borrow ends, because the line printed below has to name the
            // rule that decided even when the policy has been replaced since.
            let resolver = decision.resolver.id.clone();
            let (route, rule) = (decision.route, decision.rule);
            // A resolver asked directly is asked from the line's address for it. Its address may be
            // routed into the tunnel for the rest of the machine, and an unbound socket would follow
            // that route and be answered from the exit.
            let from = match decision.resolver.via {
                Via::Direct => self.sink.line_source(decision.resolver.address),
                Via::Tunnel => None,
            };
            let outcome = upstream.ask(query, from).await;
            // The guard is dropped with the block, before anything is done with the answer: a
            // policy being replaced must not wait on an upstream that is still thinking.
            (outcome, route, resolver, rule)
        };

        let asking = started.elapsed().as_millis();
        let reply = match outcome {
            Ok(reply) => reply,
            Err(problem) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "dns",
                    "{} {} → {resolver} (rule {rule}): {problem}",
                    type_name(asked.qtype),
                    asked.name
                );
                return failure_reply(query);
            }
        };
        self.stats.answered.fetch_add(1, Ordering::Relaxed);

        // Only an address answer to an address question becomes a route. Anything else is
        // forwarded and forgotten.
        let asks_for_addresses =
            route && matches!(asked.qtype, TYPE_A | TYPE_AAAA) && asked.qclass == CLASS_IN;
        let found = message::read_answers(&reply).unwrap_or_default();
        if asks_for_addresses && self.leases.record(&asked.name, &found, Instant::now()) {
            // What the routing table took, not what the answer held. Those differ twice over: an
            // answer repeats addresses that are already routed, and a v6 address is left out
            // entirely unless the tunnel was measured carrying v6. Counting the answer made this
            // number grow on lookups that routed nothing at all.
            let installed = self.sink.routes_changed();
            self.stats
                .routed
                .fetch_add(installed as u64, Ordering::Relaxed);
        }

        // Answers "why did that name go there" without anyone having had to ask in advance. One
        // line per query, which is cheap enough to leave on.
        info!(
            "dns",
            "{} {} → {resolver} (rule {rule}) · {} address(es){}{} · {asking} ms",
            type_name(asked.qtype),
            asked.name,
            found.len(),
            if route { ", routed" } else { "" },
            match &program {
                Some(program) => format!(" · asked by {}", program.name),
                None => String::new(),
            }
        );
        if !found.is_empty() {
            debug!(
                "dns",
                "{} = {}",
                asked.name,
                found
                    .iter()
                    .map(|r| r.address.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Some(reply)
    }

    /// Let go of leases whose time has passed, and tell the routing table if anything went.
    pub fn expire(&self) {
        let before = self.leases.len();
        if self.leases.expire(Instant::now()) {
            debug!(
                "dns",
                "{} lease(s) expired, {} held",
                before - self.leases.len(),
                self.leases.len()
            );
            self.sink.routes_changed();
        }
    }
}

/// What an install changed, for the caller that has to report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallReport {
    pub rules: usize,
    pub resolvers: usize,
    pub tunnelled: usize,
}

#[derive(Debug, thiserror::Error)]
/// Why a policy was not installed.
pub enum InstallError {
    #[error("{0}")]
    Policy(super::policy::PolicyError),
    #[error("{0}")]
    Upstream(super::upstream::UpstreamError),
    #[error(
        "the policy decides nothing about some names; add a rule matching `any`, or the machine \
         would have names this resolver refuses to answer and no other resolver to ask"
    )]
    NoCatchAll,
    #[error(
        "the resolver `{0}` is this core's own address; every name sent there would be a question asked of itself"
    )]
    Circular(String),
}

/// Listen for queries until the process ends.
pub async fn serve(resolver: Arc<Resolver>, listen: SocketAddr) -> std::io::Result<Infallible> {
    let udp = UdpSocket::bind(listen).await?;
    stop_reporting_unreachable(&udp);
    let udp = Arc::new(udp);
    let tcp = TcpListener::bind(listen).await?;

    let over_udp = serve_udp(Arc::clone(&resolver), udp);
    let over_tcp = serve_tcp(resolver, tcp);
    tokio::select! {
        stopped = over_udp => stopped,
        stopped = over_tcp => stopped,
    }
}

async fn serve_udp(resolver: Arc<Resolver>, socket: Arc<UdpSocket>) -> std::io::Result<Infallible> {
    let mut buffer = vec![0u8; 1500];
    loop {
        let (read, from) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            // Nothing that happened to one datagram is a reason to stop answering the machine's
            // questions. On Windows this is not a hypothetical: a socket reports an ICMP
            // unreachable for a datagram it sent *earlier* as an error on the *next* receive, so a
            // resolver that once answered something which has since gone away would take the whole
            // machine's DNS down with it. Measured, on this exact path.
            Err(problem) => {
                debug!("dns", "a datagram was not received: {problem}");
                continue;
            }
        };
        let query = buffer[..read].to_vec();

        // Acquired before the task is spawned, so the bound limits work in flight rather than
        // limiting it only after the tasks already exist.
        let Ok(permit) = Arc::clone(&resolver.in_flight).try_acquire_owned() else {
            continue;
        };
        let resolver = Arc::clone(&resolver);
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(reply) = resolver.answer(&query, Some(From::Udp(from))).await {
                let _ = socket.send_to(&reply, from).await;
            }
        });
    }
}

async fn serve_tcp(resolver: Arc<Resolver>, listener: TcpListener) -> std::io::Result<Infallible> {
    loop {
        let (stream, _) = listener.accept().await?;
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            // A client that hangs up, stalls, or sends nonsense is ordinary; none of it is worth
            // reporting, and all of it ends the connection and nothing else.
            let _ = converse(resolver, stream).await;
        });
    }
}

/// One TCP connection, which may carry several queries one after another.
async fn converse(resolver: Arc<Resolver>, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let peer = stream.peer_addr().ok();
    loop {
        let mut header = [0u8; 2];
        // An idle connection is closed rather than held: a resolver that let clients keep sockets
        // open forever would run out of them long before it ran out of work.
        match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut header)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()),
        }

        let length = usize::from(u16::from_be_bytes(header));
        if !(HEADER_LEN..=MAX_MESSAGE).contains(&length) {
            return Ok(());
        }
        let mut query = vec![0u8; length];
        stream.read_exact(&mut query).await?;

        let Ok(permit) = resolver.in_flight.try_acquire() else {
            return Ok(());
        };
        // Looked up in the table for the protocol the query actually arrived over. Asking the
        // UDP table about a TCP port does not merely fail — it names whichever unrelated program
        // happens to hold that number over there, and a rule about a program would then fire for
        // one that asked nothing.
        let reply = resolver.answer(&query, peer.map(From::Tcp)).await;
        drop(permit);

        let Some(reply) = reply else { return Ok(()) };
        let Ok(length) = u16::try_from(reply.len()) else {
            return Ok(());
        };
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&reply).await?;
        stream.flush().await?;
    }
}

/// Ask Windows to stop reporting an unreachable peer as a receive error.
///
/// A UDP socket has no peer, so an ICMP unreachable arriving for something it sent is news about a
/// datagram that is already gone. Windows reports it anyway, on the next receive, and a server that
/// takes it at face value stops serving. The receive loop already survives it; this stops it being
/// raised at all, which is the difference between a line in a journal and none.
///
/// Best effort by design: an older stack that does not know the option leaves the loop's own
/// handling as the answer, and that is enough on its own.
fn stop_reporting_unreachable(socket: &UdpSocket) {
    let handle = socket.as_raw_socket() as SOCKET;
    let mut off: u32 = 0;
    let mut returned: u32 = 0;
    unsafe {
        WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            std::ptr::addr_of_mut!(off).cast(),
            size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
}

/// A record type as a person reads it, for a log line that would otherwise say a number.
fn type_name(qtype: u16) -> &'static str {
    match qtype {
        TYPE_A => "A",
        TYPE_AAAA => "AAAA",
        _ => "?",
    }
}

/// Take a lock without letting a panic elsewhere become a panic here.
///
/// Nothing under this lock can panic, so it cannot be poisoned — but "cannot" is a claim about
/// today's code, and this one is taken on the path every query walks. A poisoned lock there would
/// turn one failure into a resolver that answers nothing at all, which is the machine losing its
/// name resolution over a bug that had already been survived.
fn held<T>(lock: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The one message this module writes: the query, marked as a reply that could not be served.
///
/// Written by editing the query's own header rather than by building a message. The question is
/// left exactly as it arrived, which is what a client checks, and the section counts are cleared
/// because there is nothing after the question any more.
fn failure_reply(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < HEADER_LEN {
        return None;
    }
    let mut reply = query.to_vec();
    // A reply, and recursion was available. The opcode and the id stay as they were.
    reply[2] |= 0b1000_0000;
    reply[3] = 0b1000_0000 | 2; // recursion available, rcode 2: the server failed
    // Answer, authority and additional: none.
    reply[6..12].fill(0);
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver with nothing installed, which is all the watch needs: it sits ahead of the
    /// policy on purpose, so that a name asked to prove the machine reaches here is never
    /// forwarded to an upstream that has no interest in it.
    fn bare() -> Resolver {
        struct Nowhere;
        impl RouteSink for Nowhere {
            fn routes_changed(&self) -> usize {
                0
            }
            fn line_source(&self, _: IpAddr) -> Option<IpAddr> {
                None
            }
        }
        Resolver::new(Arc::new(Leases::new()), Arc::new(Nowhere), None)
    }

    /// The one thing that proves the machine's names arrive here is one of them arriving here.
    #[test]
    fn the_watched_name_arriving_is_what_says_so() {
        let resolver = bare();
        let mut told = resolver.watch_for("Abc.masqr-check.invalid");

        // Case is not part of the question: a name is asked in whatever case the asker wrote it.
        assert!(resolver.watching_for("abc.masqr-check.invalid"));
        assert!(told.try_recv().is_ok());
    }

    /// And every other name goes on to the policy as it always did.
    #[test]
    fn another_name_is_not_the_one_being_watched_for() {
        let resolver = bare();
        let _told = resolver.watch_for("abc.masqr-check.invalid");

        assert!(!resolver.watching_for("example.com"));
    }

    /// A check that ended takes its watch with it, whether or not the name ever came — otherwise
    /// the next run of the same name would be answered by a check nobody is waiting on.
    #[test]
    fn a_watch_that_was_stopped_catches_nothing() {
        let resolver = bare();
        let _told = resolver.watch_for("abc.masqr-check.invalid");
        resolver.stop_watching();

        assert!(!resolver.watching_for("abc.masqr-check.invalid"));
    }

    /// It fires once. The name is asked again by a retry or a second program, and answering that
    /// as though it were the proof would be reporting a check that nobody ran.
    #[test]
    fn the_name_arriving_twice_is_noticed_once() {
        let resolver = bare();
        let _told = resolver.watch_for("abc.masqr-check.invalid");

        assert!(resolver.watching_for("abc.masqr-check.invalid"));
        assert!(!resolver.watching_for("abc.masqr-check.invalid"));
    }

    fn query_bytes() -> Vec<u8> {
        let mut bytes = vec![
            0x2a, 0x2a, // id
            0x01, 0x20, // a standard query, recursion desired
            0x00, 0x01, // one question
            0x00, 0x02, // and, wrongly, two answers
            0x00, 0x03, // three authority
            0x00, 0x04, // four additional
        ];
        for label in ["www", "example", "com"] {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&TYPE_A.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes
    }

    /// A failure has to be recognisable as an answer to this exact question, or the client treats
    /// it as noise and waits out its timeout anyway.
    #[test]
    fn a_failure_keeps_the_question_and_says_it_failed() {
        let query = query_bytes();
        let reply = failure_reply(&query).unwrap();

        assert_eq!(&reply[0..2], &query[0..2], "the same transaction");
        assert_eq!(reply[2] & 0b1000_0000, 0b1000_0000, "it is a reply");
        assert_eq!(reply[3] & 0x0f, 2, "the server failed");
        assert_eq!(&reply[4..6], &query[4..6], "the question is still declared");
        assert_eq!(&reply[6..12], &[0; 6], "and nothing follows it");
        assert_eq!(
            &reply[12..],
            &query[12..],
            "the question itself is untouched"
        );

        // And it is still a message this codebase can read.
        let asked = message::read_query(&reply).unwrap();
        assert_eq!(asked.name, "www.example.com");
    }

    #[test]
    fn something_too_short_to_be_a_query_gets_no_failure_either() {
        for length in 0..HEADER_LEN {
            assert!(failure_reply(&vec![0u8; length]).is_none());
        }
    }
}
