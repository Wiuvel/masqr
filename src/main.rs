//! The command line.
//!
//! ```text
//! masqr version            print the version and exit
//! masqr register           register a device, or report the one already registered
//! masqr probe              open the tunnel and resolve a name through it
//! masqr up                 bring the adapter up and carry packets until stopped
//! masqr names              leave the machine resolving names as it did, and exit
//! masqr handshake          try every ClientHello strategy against the endpoint and report
//!
//!   --identity   <path>    where the registered device is kept  (default: identity.json)
//!   --wintun     <path>    which wintun.dll to load             (default: beside this binary)
//!   --target     <prefix>  route this prefix into the tunnel; may be repeated
//!   --dns-listen <addr>    answer DNS here, once a policy is installed over the pipe
//!   --log-level  <level>   error | warn | notice | info | debug   (default: info)
//!   --handshake  <mode>    named | no-sni | split | split-slow | fronted (default: fronted)
//!   --sni        <name>    the name `fronted` presents          (default: www.cloudflare.com)
//!   --transport  <carrier> auto | h3 | h2                              (default: auto)
//!   --mtu        <bytes>   the adapter's MTU, 1280..=9000              (default: 1280)
//! ```
//!
//! `up` is the one an application starts; the rest are run by hand. Targets are accepted here for
//! convenience, but the routed set is meant to be driven over the control interface, which can
//! change it on a live tunnel.
//!
//! Every command first sweeps a name policy rule left behind by a killed run, so `names` alone is
//! a complete recovery path for a supervisor.
//!
//! See `docs/reference/cli.md`.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

mod diagnose;

use masqr::control;
use masqr::core::{Core, Counters, PathReading, Phase};
use masqr::dns;
use masqr::engine;
use masqr::queue::{PacketQueue, QueueStats};
use masqr::transport;
use masqr::transport::{Choice, Handshake};
use masqr::tun::{Adapter, Family, Prefix, parse_prefix, sys::Wintun};
use masqr::warp::{Enrolment, Identity};

#[tokio::main]
async fn main() {
    explain_panics();
    // rustls has to be told which crypto backend to use before any config is built.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("no other provider is installed");

    let (command, options) = match Options::parse(std::env::args().skip(1)) {
        Ok(parsed) => parsed,
        Err(problem) => {
            eprintln!("{problem}");
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };

    if let Some(level) = options.log_level {
        masqr::log::set_level(level);
    }
    // Set before anything opens a connection, and for the whole run: which ClientHello goes out
    // belongs to the run, not to one tunnel.
    if let Some(handshake) = options.handshake {
        masqr::transport::handshake::select(handshake);
    }
    if let Some(name) = &options.sni
        && let Err(problem) = masqr::transport::handshake::set_fronted_name(name)
    {
        eprintln!("{problem}");
        std::process::exit(2);
    }
    // The same for the carrier, and for the largest packet the tunnel will be handed, which is
    // what an HTTP/3 tunnel has to fit into one datagram before it is used.
    if let Some(choice) = options.transport {
        transport::carrier::select(choice);
    }
    transport::carrier::set_largest_packet(options.mtu.unwrap_or(TUN_MTU) as usize);

    if command == "version" {
        println!("masqr version {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    println!("masqr     {} ({command})", env!("CARGO_PKG_VERSION"));
    // Before anything that needs a name resolved, and on every command rather than only the one
    // that answers names: a rule left behind by a core that was killed points this machine at a
    // resolver that is not running, so until this runs there is no name resolution here at all —
    // including the resolution the enrolment below needs.
    let swept = masqr::names::release();
    if swept > 0 {
        println!("names     {swept} rule(s) left by an earlier run removed");
    }
    let result = match command.as_str() {
        "register" => cmd_register(&options.identity).await,
        "probe" => cmd_probe(&options.identity).await,
        "up" => cmd_up(&options).await,
        "handshake" => cmd_handshake(&options.identity, options.handshake).await,
        // The sweep above is this command. It runs before every command; this is the one with
        // nothing to do afterwards, so a supervisor can put the machine back without knowing
        // where the rule is kept.
        "names" => {
            println!("names     nothing of this core's is left on this machine");
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };

    if let Err(error) = result {
        // The whole chain, not just the outermost message: the outer one names the stage, and the
        // inner ones name what the operating system or the endpoint actually said.
        eprintln!("\nFAILED    {error}");
        let mut source = error.source();
        while let Some(cause) = source {
            eprintln!("  caused by {cause}");
            source = cause.source();
        }
        std::process::exit(1);
    }
}

const USAGE: &str = "\
usage: masqr [version|register|probe|up|names|handshake] [options]
  --identity   <path>   where the registered device is kept (default: identity.json)
  --wintun     <path>   which wintun.dll to load (default: beside this binary)
  --target     <prefix> route this prefix into the tunnel; may be repeated
  --dns-listen <addr>   answer DNS here, once a policy is installed over the pipe
  --log-level  <level>  error | warn | notice | info | debug (default: info)
  --handshake  <mode>   named | no-sni | split | split-slow | fronted (default: fronted)
  --sni        <name>   the name `fronted` presents (default: www.cloudflare.com)
  --transport  <how>    auto | h3 | h2 (default: auto: HTTP/3, HTTP/2 when it does not open)
  --mtu        <bytes>  the adapter's MTU, 1280..=9000            (default: 1280)

`handshake` opens the tunnel once per strategy and reports which of them the link let through. It
answers one question: can this core carry its own handshake, or does a DPI bypass have to be
running underneath it. Given `--handshake`, it tries that strategy alone.

`names` leaves the machine resolving names the way it did before this core ever ran, and exits. It
is what anything supervising the core can call when the core itself did not get to.";

/// What the command line said.
///
/// Named options rather than positions, because this is the line the application will write: a
/// position is easy to get subtly wrong and impossible to read back in a log.
struct Options {
    identity: PathBuf,
    wintun: Option<PathBuf>,
    targets: Vec<String>,
    /// Where the resolver listens, when there is to be one.
    ///
    /// Absent means no listener at all, which is what the checks want: they are about the tunnel,
    /// and a core that took over the machine's DNS to run them would be changing the thing it is
    /// measuring.
    dns_listen: Option<std::net::SocketAddr>,
    /// How much is said from the start. The control interface can change it later without a
    /// restart; this is only what the first lines are written at.
    log_level: Option<masqr::log::Level>,
    /// Which ClientHello the tunnel's own TLS session presents. Absent leaves the connection
    /// exactly as the core has always made it; see `transport::handshake`.
    handshake: Option<Handshake>,
    /// The name `fronted` presents in place of its default, for measuring which other names a link
    /// does not act on.
    sni: Option<String>,
    /// Which carrier the tunnel rides. Absent is `auto`: HTTP/3, and HTTP/2 when it does not open.
    transport: Option<Choice>,
    /// The adapter's MTU, for measuring whether a larger one is carried. Absent means [`TUN_MTU`].
    ///
    /// A flag rather than a constant because the answer is not ours to reason out. Over HTTP/2
    /// nothing fragments — the outer TCP segments whatever it is given — so a larger MTU buys fewer
    /// capsules for the same bytes. Over HTTP/3 each packet has to fit one datagram, and a path
    /// that cannot fit the larger size leaves the run on HTTP/2. What it costs is unknown: 1280 is
    /// what WARP itself hands out, and the endpoint may simply refuse more. That is a run, not an
    /// argument, and this is what makes the run possible without a rebuild.
    mtu: Option<u32>,
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Result<(String, Self), String> {
        let mut command = None;
        let mut options = Self {
            identity: PathBuf::from("identity.json"),
            wintun: None,
            targets: Vec::new(),
            dns_listen: None,
            log_level: None,
            handshake: None,
            sni: None,
            transport: None,
            mtu: None,
        };

        let mut args = args.peekable();
        while let Some(argument) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("{argument} needs a value after it"))
            };
            match argument.as_str() {
                "--identity" => options.identity = PathBuf::from(value()?),
                "--wintun" => options.wintun = Some(PathBuf::from(value()?)),
                "--target" => options.targets.push(value()?),
                "--log-level" => {
                    let written = value()?;
                    options.log_level = Some(
                        masqr::log::Level::parse(&written)
                            .ok_or_else(|| format!("`{written}` is not a level"))?,
                    );
                }
                "--handshake" => {
                    let written = value()?;
                    options.handshake = Some(
                        Handshake::parse(&written)
                            .ok_or_else(|| format!("`{written}` is not a handshake strategy"))?,
                    );
                }
                "--sni" => options.sni = Some(value()?),
                "--transport" => {
                    let written = value()?;
                    options.transport = Some(
                        Choice::parse(&written)
                            .ok_or_else(|| format!("`{written}` is not auto, h3 or h2"))?,
                    );
                }
                "--mtu" => {
                    let written = value()?;
                    let mtu: u32 = written
                        .parse()
                        .map_err(|_| format!("`{written}` is not a number"))?;
                    // The floor is the one every IPv6 link is required to carry; below it the
                    // adapter is not a usable link at all, whatever the tunnel would accept.
                    if !(1280..=9000).contains(&mtu) {
                        return Err(format!("{mtu} is outside 1280..=9000"));
                    }
                    options.mtu = Some(mtu);
                }
                "--dns-listen" => {
                    let written = value()?;
                    options.dns_listen = Some(
                        written
                            .parse()
                            .map_err(|_| format!("`{written}` is not an address and port"))?,
                    );
                }
                flag if flag.starts_with('-') => return Err(format!("unknown option: {flag}")),
                _ if command.is_none() => command = Some(argument),
                _ => return Err(format!("unexpected argument: {argument}")),
            }
        }
        // Said rather than quietly overridden: a split cuts TCP segments, and a run that asked for
        // both would otherwise measure something other than what it asked for.
        if options.transport == Some(Choice::H3)
            && options.handshake.is_some_and(|h| !h.works_over_quic())
        {
            return Err(
                "the split strategies cut TCP segments and have nothing to cut over h3".into(),
            );
        }
        // The name belongs to one strategy; beside another it would change nothing, and a run
        // that measured nothing should not read as one that measured something.
        if options.sni.is_some()
            && options
                .handshake
                .is_some_and(|handshake| handshake != Handshake::Fronted)
        {
            return Err(
                "--sni names what `fronted` presents; it means nothing beside another handshake"
                    .into(),
            );
        }
        Ok((command.unwrap_or_else(|| "probe".into()), options))
    }
}

async fn cmd_register(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    describe(&load_or_register(path).await?.current());
    Ok(())
}

/// The identity kept at `path`, registering a device when there is none.
///
/// Registering on the way through is what makes every command one command on a machine that has
/// never run it.
async fn load_or_register(path: &std::path::Path) -> Result<Enrolment, Box<dyn std::error::Error>> {
    let (enrolment, registered) = Enrolment::load_or_register(path).await?;
    if registered {
        println!(
            "identity  registered a new device, written to {}",
            path.display()
        );
    } else {
        println!("identity  reused from {}", path.display());
    }
    Ok(enrolment)
}

/// Which ClientHello, if any, this link lets through; see `diagnose::handshake`.
async fn cmd_handshake(
    path: &std::path::Path,
    only: Option<Handshake>,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_or_register(path).await?.current();
    describe(&identity);
    diagnose::handshake::run(&identity, only).await
}

/// One name resolved end to end through the tunnel; see `diagnose::probe`.
async fn cmd_probe(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_or_register(path).await?.current();
    describe(&identity);
    diagnose::probe::run(&identity).await
}

fn describe(identity: &Identity) {
    println!("  device    {}", identity.device_id);
    println!("  inside v4 {}", identity.assigned_v4);
    println!("  inside v6 {}", identity.assigned_v6);
    println!(
        "  endpoint  {}:443 (h3) · {}:443 (h2)",
        identity.endpoint_h3_v4(),
        identity.endpoint_h2_v4
    );
    println!("  transport {}", transport::carrier::selected().name());
    // Which ClientHello went out is the one thing about a session a journal could not say. It
    // decides whether the tunnel needs a bypass under it, so a log that omits it cannot answer
    // what the run was testing — the reason this line exists.
    let hello = masqr::transport::handshake::selected();
    match hello.sni() {
        Some(name) => println!("  hello     {} ({name})", hello.name()),
        None => println!("  hello     {} (no name)", hello.name()),
    }
}

// ── the adapter path ──────────────────────────────────────────────

/// The MTU given to the adapter.
///
/// Every packet leaving it is wrapped — in a QUIC datagram over HTTP/3, in a capsule, TLS and TCP
/// over HTTP/2. 1280 is the smallest MTU a link is allowed to have at all, so it fits under any path
/// worth serving — and it is what WARP itself hands out. HTTP/3 still has to find room for it past
/// QUIC's own overhead, which path MTU discovery does before the tunnel is used.
const TUN_MTU: u32 = 1280;

/// Where packets go when the command names no targets: the Cloudflare resolver, which also answers
/// `https://1.1.1.1/cdn-cgi/trace` and so says which colo the exit sits at.
const DEFAULT_TARGET: &str = "1.1.1.1/32";

/// How often the traffic counters are written out while the tunnel is up.
const REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the thread reading the adapter is given to leave the driver once its session ends.
///
/// It returns in microseconds when it is waiting for a packet, which is almost always. The wait
/// exists for the other case — a reader parked handing over a packet the stopped tunnel is no
/// longer taking — and it is bounded because that one never ends on its own.
const READER_HANDOVER: std::time::Duration = std::time::Duration::from_secs(2);

/// How often expired leases are collected.
const LEASE_SWEEP: std::time::Duration = std::time::Duration::from_secs(30);

/// What the adapter is called, and how it describes itself. One name for both, because both are
/// what a person looking at the network list has to recognise.
const ADAPTER_NAME: &str = "masqr";

/// Bring the adapter up, route the given prefixes into the tunnel, and carry packets until stopped.
///
/// This is the half the probe cannot reach. The probe builds its own packet and proves the
/// tunnel carries it; this proves that traffic from the operating system reaches the same place —
/// an ordinary `curl` on the machine, with nothing in it that knows a tunnel exists.
async fn cmd_up(options: &Options) -> Result<(), Box<dyn std::error::Error>> {
    let wanted = parse_targets(&options.targets)?;

    // Loading the library has no side effects, so it goes first: a missing DLL, or one whose
    // exports are not the ones expected, is worth hearing about before anything else happens.
    let wintun = Arc::new(Wintun::load(&wintun_path(options.wintun.as_deref())?)?);
    println!("wintun    loaded");

    let enrolment = load_or_register(&options.identity).await?;
    let identity = enrolment.current();
    describe(&identity);

    // The adapter comes up before the tunnel does, and stays up across every reconnect. That is
    // what keeps a routed address from falling back to the line while the tunnel is down: the route
    // stays pointed here, so packets wait for the tunnel instead of leaking past it.
    let adapter = Adapter::create(Arc::clone(&wintun), ADAPTER_NAME, ADAPTER_NAME)?;
    println!(
        "adapter   {ADAPTER_NAME}, driver {}",
        adapter.driver_version()
    );

    // The address Cloudflare assigned goes on unchanged, so nothing has to be rewritten later:
    // Windows picks it as the source of every packet routed here, and a packet therefore arrives
    // already carrying the address the endpoint expects.
    let inside: IpAddr = identity.assigned_v4.parse()?;
    adapter.add_address(inside, 32)?;
    let mtu = options.mtu.unwrap_or(TUN_MTU);
    adapter.set_mtu(Family::V4, mtu)?;

    // The v6 address goes on too, whether or not anything is routed over it yet. It costs nothing
    // while no v6 prefix points here, and it has to already be in place the moment one does — an
    // interface acquiring an address under live traffic is not a thing to arrange in a hurry.
    let inside_v6: IpAddr = identity.assigned_v6.parse()?;
    adapter.add_address(inside_v6, 128)?;
    adapter.set_mtu(Family::V6, mtu)?;
    println!("address   {inside}/32 · {inside_v6}/128, mtu {mtu}");

    let core = Arc::new(Core::new(adapter));
    for (destination, prefix) in core.set_routes(&wanted)?.added {
        println!("route     {destination}/{prefix} → {ADAPTER_NAME}");
    }

    let (reader, writer) = core.adapter().start()?.split();

    // Wintun signals readability through an event, so the read side is a blocking thread rather
    // than a task. The queue is where it meets the runtime — and it is not a plain channel: it is
    // what decides which packet goes next and which one is dropped when the tunnel cannot keep up.
    // See queue.rs; a FIFO here is what made a page of small requests wait behind a download.
    let to_tunnel = Arc::new(PacketQueue::new());
    let from_tun = Arc::clone(&to_tunnel);
    // Its ending is watched for, because the shutdown below has to know that this thread has left
    // the driver — not that it has been asked to.
    let (left, reader_left) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        while let Some(packet) = reader.recv() {
            if !from_tun.push(packet) {
                break;
            }
        }
        // Said explicitly, because the consumer is otherwise waiting on a queue that will never
        // fill again — and what it does about that is bring the whole core down, deliberately.
        from_tun.close();
        drop(reader);
        let _ = left.send(());
    });

    // The resolver exists whether or not it listens: the policy can be installed over the pipe
    // before there is anywhere to answer, and installing it is what pins the routes to the
    // resolvers that are reached through the tunnel.
    let resolver = Arc::new(dns::server::Resolver::new(
        Arc::clone(core.leases()),
        Arc::clone(&core) as Arc<dyn dns::server::RouteSink>,
        options.dns_listen,
    ));

    let mut serving = tokio::spawn(control::serve(Arc::clone(&core), Arc::clone(&resolver)));
    println!("control   {}", control::PIPE_NAME);

    let mut answering = match options.dns_listen {
        Some(listen) => {
            println!("dns       listening on {listen}");
            tokio::spawn(dns::server::serve(Arc::clone(&resolver), listen))
        }
        None => {
            println!("dns       not listening (no --dns-listen)");
            // A task that never finishes, so the loop below has one shape rather than two.
            tokio::spawn(std::future::pending())
        }
    };

    // Leases fall due on their own schedule, so something has to come round and collect them. Often
    // enough that an address stops being routed within a minute of stopping being needed, and
    // rarely enough to be nothing at all.
    let sweeping = Arc::clone(&resolver);
    tokio::spawn(async move {
        let mut every = tokio::time::interval(LEASE_SWEEP);
        loop {
            every.tick().await;
            sweeping.expire();
        }
    });

    // Held for as long as the core runs: dropping it is what stops the notifications, and what
    // makes sure none is in flight against a core that is going away.
    let line = masqr::link::watch(Arc::clone(&core));

    let mut phase = core.phase.subscribe();
    let engine = engine::run(&enrolment, &to_tunnel, &writer, &core);
    tokio::pin!(engine);

    let mut ticker = tokio::time::interval(REPORT_EVERY);
    ticker.tick().await; // the first tick is immediate, and there is nothing to report yet
    let mut ready = false;
    let stopped = loop {
        tokio::select! {
            _ = &mut engine => unreachable!("the engine stops only when it is dropped"),
            Ok(()) = phase.changed() => {
                // Cloned out of the borrow before anything is printed: holding it would block the
                // engine's next report for as long as the write to the console takes.
                let now = phase.borrow_and_update().clone();
                announce(&now, &mut ready);
            }
            _ = ticker.tick() => {
                masqr::debug!("traffic", "{}", traffic(&core.counters));
                masqr::debug!("queue", "{}", waiting(&to_tunnel.stats()));
                if let Some(reading) = core.path() {
                    masqr::debug!("path", "{}", path(&reading));
                }
            }
            _ = core.stopped() => break "asked through the control interface".to_string(),
            _ = tokio::signal::ctrl_c() => break "on Ctrl-C".to_string(),
            joined = &mut serving => break match joined {
                Ok(Err(problem)) => format!("the control interface failed: {problem}"),
                Err(problem) => format!("the control interface stopped: {problem}"),
                Ok(Ok(_)) => unreachable!("the control interface serves until it is dropped"),
            },
            joined = &mut answering => break match joined {
                Ok(Err(problem)) => format!("the resolver failed: {problem}"),
                Err(problem) => format!("the resolver stopped: {problem}"),
                Ok(Ok(_)) => unreachable!("the resolver answers until it is dropped"),
            },
        }
    };

    println!();
    // Given back before the adapter is, and unconditionally: for as long as the machine's names
    // point at a resolver that has stopped answering, it has no name resolution at all. Calling it
    // having claimed nothing is what makes this one line rather than a flag to keep in step.
    masqr::names::release();
    // The session total, said once and at every level: it is the last thing this core has to say
    // about what it carried, and the per-tick line above it is deliberately not.
    println!("traffic   {}", traffic(&core.counters));
    println!("queue     {}", waiting(&to_tunnel.stats()));
    if let Some(reading) = core.path() {
        println!("path      {}", path(&reading));
    }
    println!("stopping  {stopped}");
    // What follows is an order, not a sequence, and every step of it was learned from a crash.
    //
    // Windows stops telling this process about interfaces first: a notification arriving during
    // the rest of it would reach a core that is going away.
    masqr::debug!("stop", "no longer watching the line");
    drop(line);

    // Then the reader is asked to stop — by an event of ours, which touches nothing the driver
    // owns — and is *waited for*. Ending the session instead would wake it, and would also be a
    // call into a session another thread is inside, which is what Wintun forbids and what it
    // answers with an access violation rather than a refusal.
    masqr::debug!("stop", "asking the reader to leave");
    writer.stop_reading();
    if reader_left.recv_timeout(READER_HANDOVER).is_err() {
        // It is parked handing over a packet that nothing drains any more. Rather than take the
        // session and the adapter down underneath it, leave both to Windows: they belong to this
        // process and go when it does, along with every route.
        println!("adapter   left to Windows — the reader was still busy");
        std::process::exit(0);
    }

    // Only now is nothing inside the session, so it can end; and only once it has ended may the
    // adapter be closed, which is what dropping it below does.
    masqr::debug!("stop", "ending the session");
    writer.close();
    masqr::debug!("stop", "closing the adapter");
    Ok(())
    // Dropping the adapter here removes it from Windows, and its address and routes go with it.
}

/// Make a panic say where and why, in the journal everything else is said in.
///
/// The default hook writes to standard error in a shape nothing here reads, and a panic on a task
/// inside the runtime takes its message down with it — which is how a core comes to exit with a
/// number and nothing else to explain itself. The previous hook still runs afterwards, so a
/// backtrace asked for through the environment is still printed.
///
/// This covers panics and only panics. A fault the operating system raises — an access violation
/// inside a driver, say — is not one, and is not something a process can honestly report on its
/// own way out. That class is answered by not causing it.
fn explain_panics() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        let place = match panic.location() {
            Some(at) => format!("{}:{}", at.file(), at.line()),
            None => "somewhere with no location".to_string(),
        };
        let said = panic.payload_as_str().unwrap_or("no message");
        masqr::error!("panic", "{said} — at {place}");
        previous(panic);
    }));
}

/// Say what the engine is doing.
///
/// `ready` is printed once and only once, the first time a tunnel comes up: it is the line the
/// check script waits for, and a reconnect is not a new beginning.
fn announce(phase: &Phase, ready: &mut bool) {
    match phase {
        Phase::Connecting { attempt: 1 } => println!("tunnel    connecting"),
        Phase::Connecting { attempt } => println!("tunnel    connecting, attempt {attempt}"),
        Phase::Up { stages } => {
            println!("tunnel    up  ({stages})");
            if !*ready {
                *ready = true;
                println!();
                println!("ready     Ctrl-C to stop. Nothing outside the routes above is touched.");
                println!("          try:  curl.exe -s https://1.1.1.1/cdn-cgi/trace");
                println!();
            }
        }
        Phase::Lost {
            reason,
            retry_in,
            blocked,
        } => {
            println!("tunnel    lost — {reason}");
            if *blocked {
                println!(
                    "tunnel    nothing here is wrong: something on the way refused the handshake"
                );
            }
            println!("tunnel    retrying in {} s", retry_in.as_secs());
        }
    }
}

/// What the queue is doing, in two lines: what it was holding, then what it did about it.
///
/// Written beside the traffic counters and at the same level, because it answers the question the
/// traffic counters cannot: not how much went through, but how long it had to wait to. A slow page
/// on a tunnel that is carrying plenty is a queue problem, and until this line existed there was
/// nothing to tell that apart from a slow link.
///
/// The break is where the sentence turns, and the second line is indented to the width of the
/// `queue` tag the console prints this behind, so the continuation sits under the first half
/// rather than beside it.
///
/// `over target` is not a fault. It is the tunnel telling the connections inside it to slow down —
/// the signal the outer TCP would otherwise hide from them. Steadily zero under load is the
/// suspicious reading, not a small non-zero one. See queue.rs.
fn waiting(stats: &QueueStats) -> String {
    format!(
        "{} pkt / {} in {} flow(s) · worst wait {} ms of {} ms\n          told to slow down: {} marked, {} dropped · {} over limit · {} acks thinned · {} stale",
        stats.packets,
        bytes(stats.bytes as u64),
        stats.flows,
        stats.worst_wait.as_millis(),
        stats.interval.as_millis(),
        stats.marked,
        stats.over_target,
        stats.over_limit,
        stats.thinned,
        stats.stale
    )
}

/// The path under an HTTP/3 tunnel, as QUIC reports it.
///
/// Read beside `traffic` when a download loses packets: `lost` is the path losing this side's
/// packets, and datagrams that arrived but were never read are QUIC's receive buffer on this machine
/// overflowing. Losses on the way in that neither shows happened before QUIC saw them.
fn path(reading: &PathReading) -> String {
    format!(
        "rtt {} ms · cwnd {} · {} of {} pkt lost · {} datagram(s) in, {} read",
        reading.rtt.as_millis(),
        bytes(reading.cwnd),
        reading.lost,
        reading.sent,
        reading.datagrams,
        reading.read
    )
}

/// What has passed each way, as one line.
///
/// At debug while the tunnel runs, because it reports no change of state and would otherwise be
/// every other line in the journal. Printed once at `info` when the core stops, as the session
/// total.
fn traffic(counters: &Counters) -> String {
    let (out_packets, out_bytes) = counters.out.read();
    let (in_packets, in_bytes) = counters.back.read();
    format!(
        "out {out_packets} pkt / {} · in {in_packets} pkt / {}",
        bytes(out_bytes),
        bytes(in_bytes)
    )
}

fn bytes(count: u64) -> String {
    match count {
        0..=1023 => format!("{count} B"),
        1024..=1_048_575 => format!("{:.1} KiB", count as f64 / 1024.0),
        _ => format!("{:.1} MiB", count as f64 / 1_048_576.0),
    }
}

/// The prefixes to route into the tunnel, as written on the command line.
fn parse_targets(raw: &[String]) -> Result<std::collections::BTreeSet<Prefix>, String> {
    if raw.is_empty() {
        return parse_prefix(DEFAULT_TARGET).map(|one| [one].into());
    }
    raw.iter().map(|target| parse_prefix(target)).collect()
}

/// Where to load `wintun.dll` from: what was asked for, or the copy beside the binary.
///
/// The option exists so that a package which already ships the library somewhere can point at that
/// copy rather than carrying a second one.
fn wintun_path(asked: Option<&std::path::Path>) -> Result<PathBuf, String> {
    if let Some(asked) = asked {
        return if asked.is_file() {
            Ok(asked.to_path_buf())
        } else {
            Err(format!("no wintun.dll at {}", asked.display()))
        };
    }
    let exe =
        std::env::current_exe().map_err(|e| format!("the running binary has no path: {e}"))?;
    let beside = exe.with_file_name("wintun.dll");
    if beside.is_file() {
        Ok(beside)
    } else {
        Err(format!(
            "wintun.dll is not at {} — put it there, or name one with --wintun",
            beside.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    /// The hook has two jobs and both can be silently wrong: being installed at all, and leaving
    /// whatever was there before still running — without which asking for a backtrace through the
    /// environment would quietly stop working. The line it writes goes to the journal, which a
    /// test cannot read back; what a test can establish is that both hooks run, in that order.
    #[test]
    fn a_panic_reaches_this_hook_and_the_one_before_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static EARLIER: AtomicUsize = AtomicUsize::new(0);
        std::panic::set_hook(Box::new(|_| {
            EARLIER.fetch_add(1, Ordering::SeqCst);
        }));
        super::explain_panics();

        let escaped = std::panic::catch_unwind(|| panic!("on purpose"));

        let _ = std::panic::take_hook();
        assert!(escaped.is_err(), "the panic was not raised");
        assert_eq!(
            EARLIER.load(Ordering::SeqCst),
            1,
            "the hook that was there before this one no longer runs"
        );
    }

    use super::*;

    fn one(target: &str) -> Result<Vec<Prefix>, String> {
        parse_targets(&[target.to_string()]).map(|set| set.into_iter().collect())
    }

    /// Targets come from a command line, so the shapes a person actually types are what matter:
    /// a bare address meaning one host, an explicit prefix, and something that is neither.
    #[test]
    fn targets_are_read_the_way_they_are_written() {
        assert_eq!(
            one("1.1.1.1").unwrap(),
            vec![("1.1.1.1".parse().unwrap(), 32)]
        );
        assert_eq!(
            one("104.16.0.0/16").unwrap(),
            vec![("104.16.0.0".parse().unwrap(), 16)]
        );
        assert_eq!(
            one("2606:4700::").unwrap(),
            vec![("2606:4700::".parse().unwrap(), 128)]
        );

        assert!(
            one("1.1.1.1/33").is_err(),
            "a prefix past the family is refused"
        );
        assert!(one("1.1.1.1/").is_err(), "an empty prefix is refused");
        assert!(one("not-an-address").is_err());
    }

    /// No targets means the default, so that `masqr up` on its own is a complete check.
    #[test]
    fn no_targets_means_the_resolver_that_serves_the_trace_page() {
        let parsed: Vec<Prefix> = parse_targets(&[]).unwrap().into_iter().collect();
        assert_eq!(parsed, vec![("1.1.1.1".parse().unwrap(), 32)]);
    }

    /// The same target twice is one route, not two attempts to install one.
    #[test]
    fn a_repeated_target_is_one_route() {
        let asked = ["1.1.1.1".to_string(), "1.1.1.1/32".to_string()];
        assert_eq!(parse_targets(&asked).unwrap().len(), 1);
    }
}
