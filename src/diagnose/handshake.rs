//! `masqr handshake`: which ClientHello, over which carrier, this link lets carry a tunnel.

use masqr::transport::{self, Carrier, Choice, Handshake};
use masqr::warp::Identity;

use super::packets::{icmp_echo_reply, ipv4_icmp_echo};

/// Which ClientHello, if any, this link lets through.
///
/// One tunnel per strategy, opened all the way to CONNECT-IP and then held: a handshake can
/// survive and still reach an endpoint that will not carry packets for this identity, and an
/// earlier version that stopped at CONNECT-IP reported strategies as working which could not hold
/// a session for ten seconds.
///
/// Reading the result:
///
/// * **`named` held.** This link does not filter the name today; nothing here is needed.
/// * **`named` cut, something else held.** The core can carry its own handshake, and the tunnel no
///   longer needs a bypass running underneath it.
/// * **`named` cut, `fronted` held, nothing else.** The link classifies the flow by the name and
///   then acts on it. Omitting the name does not help — unclassifiable is treated the same. What
///   carries is presenting a name the link does not act on.
/// * **Something opened and then stopped answering.** The endpoint took the connection and did
///   not keep it, so the strategy is unusable whatever its handshake looked like.
/// * **Nothing opened, `fronted` included.** The address is blocked, not the name, and none of
///   this is the remedy.
///
/// `only` narrows the run to one strategy, over each carrier it works over. That is how a name for
/// `fronted` is measured on its own: its rows are the answer, and the verdict below — which reads
/// what held against what did not — has nothing to compare them with, so it is not printed.
pub async fn run(
    identity: &Identity,
    only: Option<Handshake>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inside: std::net::Ipv4Addr = identity.assigned_v4.parse()?;

    // Which interface the connection actually leaves by, before a single strategy is tried.
    //
    // This is the check that makes the rest of the output mean anything. A full-tunnel client on
    // this machine — a proxy in TUN mode, another VPN — takes the default route, and every
    // strategy then travels inside *it*: the filtering on the line never sees the ClientHello, so
    // every strategy "works" and the run has measured someone else's tunnel. The local address
    // says so plainly: it belongs to the interface the packets left by.
    match tokio::net::TcpStream::connect((identity.endpoint_h2_v4.as_str(), 443)).await {
        Ok(probe) => match probe.local_addr() {
            Ok(local) => println!(
                "leaving   by {} (this machine's address on that path)",
                local.ip()
            ),
            Err(problem) => println!("leaving   could not be established: {problem}"),
        },
        Err(problem) => println!("leaving   the endpoint is not reachable at all: {problem}"),
    }
    println!("          If that is not this machine's address on the line itself, every result");
    println!("          below describes whatever holds the default route — not the line.");
    // The local address cannot show this one: a packet-level bypass rewrites what leaves the same
    // interface, so it fronts the handshake without changing where it left from. Nothing here can
    // see it, which is why it is said rather than checked.
    println!("          A DPI bypass would front these from that same address and not show here.");
    println!("          Stop it before trusting the table.");
    println!();
    println!("strategy     over  what it does                        result");

    let mut opened = Vec::new();
    for strategy in Handshake::ALL
        .into_iter()
        .filter(|strategy| only.is_none_or(|only| only == *strategy))
    {
        masqr::transport::handshake::select(strategy);
        // Each name over both carriers: the name is read in QUIC's Initial as it is in TLS's
        // ClientHello, and the two paths can be treated differently. The splits are TCP's alone.
        let carriers: &[Carrier] = if strategy.works_over_quic() {
            &[Carrier::H2, Carrier::H3]
        } else {
            &[Carrier::H2]
        };
        for &carrier in carriers {
            transport::carrier::select(match carrier {
                Carrier::H2 => Choice::H2,
                Carrier::H3 => Choice::H3,
            });
            let started = std::time::Instant::now();
            // The same timeout the engine gives a real attempt: a strategy that only succeeds
            // after longer than the engine would wait has not succeeded.
            let attempt = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                transport::connect(identity),
            );
            let outcome = match attempt.await {
                Ok(Ok((tunnel, stages))) => {
                    let opening =
                        format!("opened in {} ms ({stages})", started.elapsed().as_millis());
                    match carry_and_hold(tunnel, inside).await {
                        Ok(carried) => {
                            opened.push((strategy, carrier));
                            format!("{opening}, {carried}")
                        }
                        // Deliberately NOT counted as opened. A strategy that cannot carry traffic
                        // is not one the engine can use, and reporting it beside the ones that can
                        // is what let a session that merely opened be taken for one that works.
                        Err(why) => format!("{opening}, {why}"),
                    }
                }
                Ok(Err(problem)) => problem.to_string(),
                Err(_) => "no answer within 20 s".to_string(),
            };
            println!(
                "{:<12} {:<5} {:<35} {outcome}",
                strategy.name(),
                carrier.name(),
                strategy.describes()
            );
        }
    }

    if only.is_some() {
        return Ok(());
    }

    // The verdict about the name is read off HTTP/2, where every strategy was tried; HTTP/3's
    // result follows it as a line of its own.
    let over = |wanted: Carrier| -> Vec<Handshake> {
        opened
            .iter()
            .filter(|(_, carrier)| *carrier == wanted)
            .map(|(strategy, _)| *strategy)
            .collect()
    };
    let (over_h2, over_h3) = (over(Carrier::H2), over(Carrier::H3));
    println!();
    match over_h2.as_slice() {
        [] => println!(
            "verdict   nothing opened. Either the endpoint address is blocked outright, or this 
                       machine has no path to it at all — neither is answered by the ClientHello."
        ),
        // Two questions are being asked at once, and only one of them can be answered here.
        // The endpoint's willingness travels with the strategy; the link's is a property of where
        // the run happened. Saying so keeps a run on an unfiltered link from reading as a failure:
        // it settles the half that does not depend on the link.
        _ if over_h2.contains(&Handshake::Named) => {
            println!(
                "verdict   this link did not filter the expected name, so it has said nothing about
                           whether removing the name defeats one that does. Measure again on a link
                           that cuts `named`."
            );
            println!(
                "          Settled regardless of the link — the endpoint itself accepts: {}",
                over_h2
                    .iter()
                    .map(|s| s.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if over_h2.contains(&Handshake::NoSni) {
                println!(
                    "          `no-sni` among them means the endpoint does not route MASQUE by the name
                               at all: the key pinned from registration verified without one. Only the
                               link's half of the question is left."
                );
            }
        }
        // The endpoint answers under any name — the key pinned at registration verifies, so this
        // is the real endpoint and not something terminating in between. When this is the only
        // strategy left standing, the link is reading the name and acting on the flow it names;
        // omitting the name (`no-sni`) lands in the same bucket, which is why it is not a way out.
        [only] if *only == Handshake::Fronted => {
            println!(
                "verdict   the name is what is acted on, and an unfiltered Cloudflare name is what
                           carries. The endpoint answers under it — the pinned key verified — so this
                           is usable, not a control."
            );
            println!("          Run the tunnel with `--handshake fronted` and no bypass under it.");
        }
        usable => {
            println!(
                "verdict   this core can carry its own handshake on this link, with: {}",
                usable
                    .iter()
                    .map(|s| s.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "          Run the tunnel with `--handshake <one of those>` and no bypass under it."
            );
        }
    }
    if over_h3.is_empty() {
        println!("over h3   nothing held: the tunnel falls through to h2 on this link.");
    } else {
        println!(
            "over h3   held with: {}. `--transport auto` tries h3 first with the chosen handshake.",
            over_h3
                .iter()
                .map(|s| s.name())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// How much has to go through the tunnel before a strategy counts as usable, and in what shape.
///
/// Pings alone were not enough, and finding that out cost a wrong conclusion. A filtered link does
/// not only match names — it also watches how much a connection has carried, and a Cloudflare
/// connection that goes quiet after the first tens of kilobytes is a known shape of that. Sixty-
/// four echoes of 1200 bytes put roughly 77 KiB across in each direction, which is far enough past
/// any such threshold to be a real answer rather than a hopeful one.
const CARRY_PAYLOAD: usize = 1200;
const CARRY_ROUNDS: usize = 8;
const CARRY_PER_ROUND: u16 = 8;
const CARRY_WAIT: std::time::Duration = std::time::Duration::from_secs(3);
const CARRY_SPACING: std::time::Duration = std::time::Duration::from_millis(60);

/// Put real traffic through the tunnel, then ask whether it is still there.
///
/// The order is the point. Carrying first is what would trip a limit on volume; pinging afterwards
/// is what notices that it did. A run that pinged an idle tunnel and stopped — as this command
/// first did — reports a strategy as working on evidence that never touched the thing most likely
/// to break it.
///
/// Echo requests rather than anything higher up, because they need no TCP stack of this core's own
/// and the replies make the return path measurable too: a tunnel that carries out and not back is
/// still a tunnel that does not work.
async fn carry_and_hold(
    tunnel: transport::Tunnel,
    inside: std::net::Ipv4Addr,
) -> Result<String, String> {
    const TARGET: [u8; 4] = [1, 1, 1, 1];
    const ID: u16 = 0x6d71;

    let (mut sender, mut receiver, mut health) = tunnel.split();
    let payload = vec![0x5a; CARRY_PAYLOAD];
    let mut sent_bytes = 0usize;
    let mut replies = 0usize;
    let mut seq = 0u16;

    for _round in 1..=CARRY_ROUNDS {
        for _ in 0..CARRY_PER_ROUND {
            seq += 1;
            let packet = ipv4_icmp_echo(inside.octets(), TARGET, ID, seq, &payload);
            sent_bytes += packet.len();
            sender.send(&mut [packet]).await.map_err(|e| {
                format!(
                    "the tunnel stopped taking packets after {}: {e}",
                    kib(sent_bytes)
                )
            })?;
            // Spaced rather than blasted: a burst is what makes a well-behaved host stop replying,
            // and this is measuring the path, not the host's patience.
            tokio::time::sleep(CARRY_SPACING).await;
        }

        // Replies for this round only. A round that brings back nothing is the failure this is
        // looking for: the tunnel took the bytes and the far side never heard them.
        let mut this_round = 0usize;
        let deadline = tokio::time::Instant::now() + CARRY_WAIT;
        while this_round < usize::from(CARRY_PER_ROUND) {
            match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Ok(Some(packet))) => {
                    if icmp_echo_reply(&packet, inside.octets(), ID).is_some() {
                        this_round += 1;
                        replies += 1;
                    }
                }
                Ok(Ok(None)) => return Err(format!("the tunnel closed after {}", kib(sent_bytes))),
                Ok(Err(e)) => {
                    return Err(format!("the tunnel failed after {}: {e}", kib(sent_bytes)));
                }
                Err(_) => break,
            }
        }
        if this_round == 0 {
            // Silence has two causes and they mean opposite things, so the tunnel is asked before
            // anything is concluded. The far side rate-limits echo replies — that is ordinary, and
            // it leaves the tunnel perfectly alive. A path cut off under load leaves it dead.
            // Reporting the first as the second is how a diagnostic invents a finding.
            let alive = matches!(
                tokio::time::timeout(HOLD_TIMEOUT, health.probe()).await,
                Ok(Ok(_))
            );
            return if alive {
                // The tunnel answers, so only the far host went quiet: ordinary rate limiting, and
                // nothing at all about the path.
                Err(format!(
                    "only the target went quiet at {} (tunnel alive)",
                    kib(sent_bytes)
                ))
            } else {
                // The tunnel took the bytes and stopped being a tunnel. That is the path.
                Err(format!("DIED after carrying {}", kib(sent_bytes)))
            };
        }
    }

    // Still there after the load? The engine asks exactly this way.
    for round in 1..=HOLD_ROUNDS {
        tokio::time::sleep(HOLD_EVERY).await;
        match tokio::time::timeout(HOLD_TIMEOUT, health.probe()).await {
            Ok(Ok(_)) => {}
            Ok(Err(problem)) => {
                return Err(format!(
                    "carried {}, then failed on ping {round}: {problem}",
                    kib(sent_bytes)
                ));
            }
            Err(_) => {
                return Err(format!(
                    "carried {}, then no answer to ping {round} within {} s",
                    kib(sent_bytes),
                    HOLD_TIMEOUT.as_secs()
                ));
            }
        }
    }

    Ok(format!(
        "carried {} · {replies}/{seq} back · held {HOLD_ROUNDS} pings",
        kib(sent_bytes)
    ))
}

fn kib(bytes: usize) -> String {
    format!("{:.1} KiB", bytes as f64 / 1024.0)
}

/// How many pings a strategy has to survive before it counts as usable.
///
/// The engine asks every five seconds and gives up after five. Two rounds is the smallest number
/// that distinguishes a tunnel which is up from one which merely opened — the failure in the field
/// arrived within the first two.
const HOLD_ROUNDS: usize = 2;
const HOLD_EVERY: std::time::Duration = std::time::Duration::from_secs(5);
const HOLD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
