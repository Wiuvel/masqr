//! The control interface: a named pipe the application drives the core through.
//!
//! A pipe rather than a localhost port, because this process is elevated and a port is not.
//! Anything running as the user could connect to a port, which would mean inventing a secret and
//! somewhere to keep it. A pipe carries its own access list, so Windows answers the question before
//! a byte is read — only Administrators and the system may open it.
//!
//! One JSON object per line in each direction. Requests and replies are small, and line-delimited
//! keeps the interface drivable by hand.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use crate::core::{Core, Phase};
use crate::dns::policy::PolicyInput;
use crate::dns::server::Resolver;
use crate::tun::parse_prefix;

/// Where the application looks for the core.
pub const PIPE_NAME: &str = r"\\.\pipe\masqr";

/// Who may open the pipe: the built-in Administrators group and the system, and nobody else.
///
/// `P` makes it protected, so nothing is inherited into it — without that, a permissive default on
/// the pipe namespace would be added to what is written here rather than replaced by it.
const PIPE_ACCESS: &str = "D:P(A;;GA;;;BA)(A;;GA;;;SY)";

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum Request {
    /// Everything the application shows about the tunnel.
    Status,
    /// Make the routed set exactly this. Prefixes are `address` or `address/length`.
    ///
    /// `ipv6` says whether the application wants the tunnel to carry IPv6 at all. Whether it
    /// actually does is measured, not declared, and both have to agree before a v6 prefix is
    /// installed.
    Routes {
        set: Vec<String>,
        #[serde(default)]
        ipv6: bool,
    },
    /// Replace the DNS policy: which upstream answers a name, and whose answers become routing.
    ///
    /// Replaced whole and never merged, so the core is never holding half of an old policy.
    Dns {
        #[serde(flatten)]
        policy: PolicyInput,
    },
    /// How much the core says about what it is doing. Takes effect on the next line.
    Log { level: String },
    /// Take the machine's names over, or give them back.
    ///
    /// Taking them over is proved rather than assumed, and a claim that could not be proved is
    /// undone before the reply is written — so `ok: false` means the machine is exactly as it was.
    Names { claim: bool },
    /// Change the SNI name for the `fronted` strategy.
    Sni { name: String },
    /// Throw away the tunnel that is up and open a fresh one. Routing does not move.
    Reconnect,
    /// Put the adapter away and exit.
    Stop,
}

/// Accept connections until the process ends.
pub async fn serve(core: Arc<Core>, resolver: Arc<Resolver>) -> std::io::Result<Infallible> {
    let access = Access::from_sddl(PIPE_ACCESS)?;
    // `first_pipe_instance` on the first one only: it is what makes a second core refuse to start
    // rather than quietly share the name with the one already running.
    let mut server = access.create(true)?;
    loop {
        server.connect().await?;
        let connected = server;
        // The next instance is created before the current one is handled, so a caller that connects
        // while another is being answered is never turned away.
        server = access.create(false)?;

        let core = Arc::clone(&core);
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            // A caller that hangs up mid-sentence is ordinary, not an error worth reporting.
            let _ = converse(connected, core, resolver).await;
        });
    }
}

async fn converse(
    pipe: NamedPipeServer,
    core: Arc<Core>,
    resolver: Arc<Resolver>,
) -> std::io::Result<()> {
    let (reading, mut writing) = tokio::io::split(pipe);
    let mut lines = BufReader::new(reading).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Request>(&line) {
            Ok(request) => answer(request, &core, &resolver).await,
            Err(problem) => refusal(&problem.to_string()),
        };
        writing.write_all(reply.as_bytes()).await?;
        writing.write_all(b"\n").await?;
        writing.flush().await?;
    }
    Ok(())
}

async fn answer(request: Request, core: &Core, resolver: &Resolver) -> String {
    match request {
        Request::Status => status(core, resolver),
        Request::Routes { set, ipv6 } => match prefixes(&set) {
            Err(problem) => refusal(&problem),
            Ok(wanted) => {
                core.set_wants_ipv6(ipv6);
                match core.set_routes(&wanted) {
                    Err(problem) => refusal(&problem.to_string()),
                    Ok(change) => serde_json::json!({
                        "ok": true,
                        "added": written(change.added.iter().copied()),
                        "removed": written(change.removed.iter().copied()),
                    })
                    .to_string(),
                }
            }
        },
        Request::Dns { policy } => match resolver.install(policy).await {
            Err(problem) => refusal(&problem.to_string()),
            Ok(report) => {
                // The machine has to be told to forget what it already knows, or the new policy
                // decides nothing about any name that was asked before it arrived — the answer is
                // cached, nobody asks again, and the address in it is one this core never handed
                // out and so never routed. That is what a rule added while the tunnel is up looks
                // like when it appears to do nothing at all.
                crate::names::forget_answers();
                serde_json::json!({
                    "ok": true,
                    "rules": report.rules,
                    "resolvers": report.resolvers,
                    "tunnelled": report.tunnelled,
                })
                .to_string()
            }
        },
        Request::Log { level } => match crate::log::Level::parse(&level) {
            None => refusal(&format!(
                "`{level}` is not a level; it is one of error, warn, notice, info, debug"
            )),
            Some(level) => {
                let before = crate::log::level();
                crate::log::set_level(level);
                // Only when it moved. The application sends the level alongside every policy edit,
                // and a journal that keeps reporting being told what it was already doing has that
                // much less room for the lines that say something changed.
                if level != before {
                    notice!("log", "level is now {}", level.word().to_ascii_lowercase());
                }
                serde_json::json!({ "ok": true, "level": level.word().to_ascii_lowercase() })
                    .to_string()
            }
        },
        Request::Names { claim } => match (claim, resolver.answers_at()) {
            (false, _) => {
                let removed = crate::names::release();
                serde_json::json!({ "ok": true, "claimed": false, "removed": removed }).to_string()
            }
            // Nothing to point the machine at. A core that is not answering names cannot be
            // the machine's resolver, and claiming otherwise leaves it pointed at a closed
            // socket.
            (true, None) => refusal("this core is not answering names"),
            (true, Some(at)) => match crate::names::take_over(resolver, at.ip()).await {
                Ok(()) => {
                    notice!("names", "every name on this machine is answered here");
                    serde_json::json!({ "ok": true, "claimed": true }).to_string()
                }
                Err(problem) => refusal(&problem.to_string()),
            },
        },
        Request::Sni { name } => match crate::transport::handshake::set_fronted_name(&name) {
            Err(problem) => refusal(&problem),
            Ok(_) => serde_json::json!({ "ok": true }).to_string(),
        },
        Request::Reconnect => {
            core.reconnect();
            serde_json::json!({ "ok": true }).to_string()
        }
        Request::Stop => {
            core.stop();
            serde_json::json!({ "ok": true }).to_string()
        }
    }
}

fn status(core: &Core, resolver: &Resolver) -> String {
    let (out_packets, out_bytes) = core.counters.out.read();
    let (in_packets, in_bytes) = core.counters.back.read();

    // Borrowed and dropped inside this statement: holding a watch borrow across anything else can
    // block the engine's next update.
    let phase = core.phase.borrow().clone();
    let mut state = serde_json::json!({ "state": phase.name() });
    match &phase {
        Phase::Connecting { attempt } => state["attempt"] = (*attempt).into(),
        Phase::Up { stages } => {
            state["transport"] = stages.carrier().name().into();
            state["stages"] = stages
                .steps()
                .into_iter()
                .map(|(name, ms)| (format!("{name}_ms"), serde_json::Value::from(ms as u64)))
                .collect::<serde_json::Map<_, _>>()
                .into();
            if let Some(path) = core.path() {
                state["path"] = serde_json::json!({
                    "rtt_ms": path.rtt.as_millis() as u64,
                    "cwnd": path.cwnd,
                    "sent": path.sent,
                    "lost": path.lost,
                    "datagrams": path.datagrams,
                    "read": path.read,
                });
            }
        }
        Phase::Lost {
            reason,
            retry_in,
            blocked,
        } => {
            state["reason"] = reason.as_str().into();
            state["retry_in_ms"] = (retry_in.as_millis() as u64).into();
            state["blocked"] = (*blocked).into();
        }
    }

    let dns = resolver.stats();
    serde_json::json!({
        "ok": true,
        "tunnel": state,
        "routes": written(core.routes().iter().copied()),
        "traffic": {
            "out": { "packets": out_packets, "bytes": out_bytes },
            "back": { "packets": in_packets, "bytes": in_bytes },
        },
        "level": crate::log::level().word().to_ascii_lowercase(),
        "ipv6": match core.ipv6_support() {
            crate::core::Ipv6Support::Carries => "carried",
            crate::core::Ipv6Support::DoesNot => "not carried",
            crate::core::Ipv6Support::Unknown => "not measured yet",
        },
        "dns": {
            "queries": dns.queries.load(Relaxed),
            "answered": dns.answered.load(Relaxed),
            "failed": dns.failed.load(Relaxed),
            "routed": dns.routed.load(Relaxed),
            // How many addresses are routed because a name resolved to them, as distinct from the
            // prefixes the application asked for.
            "leases": core.leases().len(),
        },
    })
    .to_string()
}

fn refusal(problem: &str) -> String {
    serde_json::json!({ "ok": false, "error": problem }).to_string()
}

fn prefixes(written: &[String]) -> Result<BTreeSet<crate::tun::Prefix>, String> {
    written.iter().map(|one| parse_prefix(one)).collect()
}

fn written(prefixes: impl Iterator<Item = crate::tun::Prefix>) -> Vec<String> {
    prefixes
        .map(|(address, length)| format!("{address}/{length}"))
        .collect()
}

/// A security descriptor built from SDDL, kept alive for as long as pipes are made with it.
struct Access {
    descriptor: PSECURITY_DESCRIPTOR,
}

// The descriptor is a plain allocation that nothing mutates after it is built; it is only ever read
// by the kernel when a pipe instance is created.
unsafe impl Send for Access {}
unsafe impl Sync for Access {}

impl Access {
    fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let built = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if built == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { descriptor })
    }

    fn create(&self, first: bool) -> std::io::Result<NamedPipeServer> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        };
        // Safe because the attributes and the descriptor they point at both outlive this call, and
        // the pipe copies what it needs from them.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .create_with_security_attributes_raw(
                    PIPE_NAME,
                    &mut attributes as *mut _ as *mut c_void,
                )
        }
    }
}

impl Drop for Access {
    fn drop(&mut self) {
        unsafe { LocalFree(self.descriptor) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire shape, checked here rather than discovered at run time.
    ///
    /// A tagged enum whose variant carries a flattened struct is the one part of this protocol that
    /// can fail quietly: serde buffers the object to find the tag, and a shape it cannot re-read
    /// comes back as a parse error on a request that looks perfectly good in a log.
    #[test]
    fn a_policy_arrives_as_one_object_with_the_command_in_it() {
        let line = r#"{
            "command": "dns",
            "resolvers": [
                { "id": "home", "kind": "plain", "address": "192.168.1.1", "via": "direct" },
                { "id": "warp", "kind": "doh", "url": "https://cloudflare-dns.com/dns-query",
                  "address": "1.1.1.1", "via": "tunnel" }
            ],
            "rules": [
                { "match": { "suffix": "youtube.com" }, "resolver": "warp", "route": true },
                { "match": "any", "resolver": "home" }
            ]
        }"#;

        let Request::Dns { policy } = serde_json::from_str(line).expect("the policy parses") else {
            panic!("the command was read as something else");
        };
        assert_eq!(policy.resolvers.len(), 2);
        assert_eq!(policy.rules.len(), 2);
        assert!(policy.rules[0].route, "route is read, not defaulted away");
        assert!(!policy.rules[1].route, "and defaults to false when absent");
    }

    #[test]
    fn the_other_commands_still_read_as_themselves() {
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"command":"status"}"#),
            Ok(Request::Status)
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"command":"reconnect"}"#),
            Ok(Request::Reconnect)
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"command":"stop"}"#),
            Ok(Request::Stop)
        ));
        let Ok(Request::Routes { set, ipv6 }) =
            serde_json::from_str::<Request>(r#"{"command":"routes","set":["1.1.1.1/32"]}"#)
        else {
            panic!("routes did not read as itself");
        };
        assert_eq!(set, vec!["1.1.1.1/32"]);
        // Absent means no: carrying a family the application did not ask for is the one direction
        // a default must never take on its own.
        assert!(!ipv6);

        let Ok(Request::Routes { ipv6, .. }) =
            serde_json::from_str::<Request>(r#"{"command":"routes","set":[],"ipv6":true}"#)
        else {
            panic!("routes did not read as itself");
        };
        assert!(ipv6);
    }

    /// A request naming a command nobody implements is a refusal, not a panic and not a default.
    /// The level is a word, and a word nobody recognises has to be refused rather than read as a
    /// default: a request to see more that quietly changes nothing is worse than one that fails.
    #[test]
    fn the_log_level_is_a_command_of_its_own() {
        let Ok(Request::Log { level }) =
            serde_json::from_str::<Request>(r#"{"command":"log","level":"debug"}"#)
        else {
            panic!("the level did not read as itself");
        };
        assert_eq!(
            crate::log::Level::parse(&level),
            Some(crate::log::Level::Debug)
        );
        assert_eq!(crate::log::Level::parse("loud"), None);
    }

    #[test]
    fn an_unknown_command_is_refused() {
        assert!(serde_json::from_str::<Request>(r#"{"command":"launch"}"#).is_err());
    }
}
