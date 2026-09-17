//! Taking over the machine's name resolution, and giving it back.
//!
//! The answer is what creates the route, so a query answered by anything else is a connection that
//! leaves over the line instead of the tunnel. Every name has to arrive here; "most of them" is not
//! a usable state.
//!
//! **Adapter DNS settings are not touched.** Writing to them overwrites a choice the machine's
//! owner made, which then has to be recorded, restored correctly, and restored at all — and until
//! it is, a machine pointed at a resolver that no longer exists has no name resolution. The record
//! is the fragile part, so there is no record: this writes one rule to the name resolution policy
//! instead — *every name is answered by the resolver at this address*. That rule sits above the
//! choice of which adapter's servers to ask, so interface metrics, the default route and parallel
//! queries across adapters do not affect it, and undoing it is deleting a rule of this core's own.
//!
//! The rule carries a mark. A core that was killed rather than stopped leaves the rule behind, and
//! the next run sweeps by that mark — no state has to survive in between.
//!
//! **Why a rule and not a route.** This core owns an adapter and Windows removes it, and its
//! routes, when the process ends; routing the machine's resolver into the tunnel would need no
//! cleanup. It is not done because that resolver is very often the default gateway, and a host
//! route for the gateway takes it away from the adapter that reaches it — the link itself stops
//! working. Safe only when the resolver happens to be a public address is not safe enough.

use std::net::IpAddr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, FreeLibrary, NO_ERROR};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_MULTI_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegEnumKeyExW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

use crate::dns::server::Resolver;
use crate::tun::sys::wide;

/// Where Windows keeps the rules that say which resolver answers which names.
const RULES: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// The rule this core writes.
///
/// A fixed name rather than a fresh one per run, so a core that was killed leaves exactly one rule
/// behind however many times it happens, and the next one replaces it rather than adding to it. A
/// pile of rules is not merely untidy: the name resolution policy is consulted on every query.
const RULE: &str = "{6D617371-7200-4000-8000-6E616D657301}";

/// What marks a rule as this core's, carried on the rule itself.
///
/// Everything the sweep needs is here rather than in a record kept alongside, so a run can repair
/// what an earlier one left with nothing having survived in between, and cannot remove a rule
/// belonging to something else.
const MARK: &str = "masqr";

/// The namespace meaning every name.
const EVERY_NAME: &str = ".";

/// The bit saying the rule names ordinary DNS servers.
const USES_GENERIC_SERVERS: u32 = 0x8;

/// The rule format this is written in.
const RULE_VERSION: u32 = 2;

/// How long the machine is given to start using the rule.
///
/// The client picks the change up on its own; this is the ceiling on waiting for it, not an
/// expected duration. Past it the claim is treated as not having taken, which costs a fallback
/// rather than a machine that resolves nothing.
const CARRIED_WITHIN: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
/// Why the machine's names could not be pointed at this core.
pub enum NameError {
    #[error("the name policy could not be written ({0} failed with error {1})")]
    Registry(&'static str, u32),
    #[error("the name policy was written but the machine did not use it")]
    NotCarried,
}

/// Point every name on this machine at the resolver at `server`, and prove that it worked.
///
/// The proof is the point. `claim` writes a rule; whether the machine then uses it is a different
/// question, and the only honest way to ask it is to have the operating system resolve a name and
/// see whether it arrives here. A takeover reported without having happened is the one outcome
/// with no symptom of its own: names keep resolving, from somewhere else, and every address they
/// return is one the tunnel never hears about.
///
/// A claim that cannot be proved is undone before this returns, so a caller that falls back to
/// something else is not falling back onto a rule still in place.
pub async fn take_over(resolver: &Resolver, server: IpAddr) -> Result<(), NameError> {
    claim(server)?;

    let name = canary();
    let arrived = resolver.watch_for(&name);
    // Asked of the operating system rather than of this resolver: what is being measured is the
    // path an ordinary program's name takes, and asking the socket directly would prove only that
    // the socket is open. Blocking, because that is the only way to ask, and detached, because the
    // answer is not what is being waited for — its arrival here is.
    tokio::task::spawn_blocking({
        let name = name.clone();
        move || {
            use std::net::ToSocketAddrs;
            let _ = (name.as_str(), 0u16).to_socket_addrs();
        }
    });

    let carried = tokio::time::timeout(CARRIED_WITHIN, arrived).await.is_ok();
    resolver.stop_watching();
    if !carried {
        release();
        return Err(NameError::NotCarried);
    }
    // What the machine already knows was answered by somebody else, and it will not ask again
    // until those answers run out.
    forget_answers();
    Ok(())
}

/// Make the machine forget the answers it already has.
///
/// A rule about a name that was resolved a minute ago decides nothing. The answer sits in the
/// machine's resolver cache; the program that has it never asks again; and the address it goes on
/// using is one this core never handed out and therefore never routed. The rule looks installed —
/// it is installed — and it does nothing at all until its predecessor's time to live runs out,
/// which is minutes and is indistinguishable from a rule that was never installed.
///
/// So every change to what the answers would be takes the old ones with it: the policy being
/// replaced, the names being taken over, and the names being given back.
pub fn forget_answers() -> bool {
    let library = unsafe {
        LoadLibraryExW(
            wide("dnsapi.dll").as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if library.is_null() {
        return false;
    }
    let entry = unsafe { GetProcAddress(library, c"DnsFlushResolverCache".as_ptr().cast()) };
    let flushed = match entry {
        Some(address) => {
            let flush: unsafe extern "system" fn() -> i32 = unsafe { std::mem::transmute(address) };
            unsafe { flush() != 0 }
        }
        None => false,
    };
    unsafe { FreeLibrary(library) };
    flushed
}

/// Remove every rule this core wrote, and say how many there were.
///
/// Safe to call having written none, so it can be the first thing a run does: a rule found here
/// belongs to a core that did not get to remove its own.
pub fn release() -> usize {
    let Some(rules) = open(RULES, KEY_READ | KEY_WRITE) else {
        return 0;
    };
    let ours: Vec<String> = subkeys(rules)
        .into_iter()
        .filter(|name| {
            open(&format!(r"{RULES}\{name}"), KEY_READ)
                .map(|rule| {
                    let comment = read_text(rule, "Comment");
                    close(rule);
                    comment.as_deref() == Some(MARK)
                })
                .unwrap_or(false)
        })
        .collect();

    let mut removed = 0;
    for name in ours {
        let wide_name = wide(&name);
        if unsafe { RegDeleteKeyExW(rules, wide_name.as_ptr(), 0, 0) } == NO_ERROR {
            removed += 1;
        }
    }
    close(rules);
    // The answers this core gave must not outlive the rule that sent the questions here: they were
    // chosen for a routing table that is about to stop existing.
    if removed > 0 {
        forget_answers();
    }
    removed
}

/// Write the rule. Whether the machine goes on to use it is `take_over`'s question, not this one's.
fn claim(server: IpAddr) -> Result<(), NameError> {
    let rule = create(&format!(r"{RULES}\{RULE}"))?;
    let written = (|| {
        set_number(rule, "Version", RULE_VERSION)?;
        set_names(rule, "Name", EVERY_NAME)?;
        set_text(rule, "GenericDNSServers", &server.to_string())?;
        set_number(rule, "ConfigOptions", USES_GENERIC_SERVERS)?;
        set_text(rule, "Comment", MARK)?;
        set_text(rule, "DisplayName", MARK)
    })();
    close(rule);
    written
}

/// A name nothing answers, in the namespace reserved for exactly that, different every time.
///
/// Different every time because a name asked once may be answered from a cache the second time,
/// and a query answered without reaching this resolver would prove the opposite of what is being
/// measured.
fn canary() -> String {
    format!("{:016x}.masqr-check.invalid", rand::random::<u64>())
}

// ── the registry, at the level this module needs it ─────────────────────────

fn create(path: &str) -> Result<HKEY, NameError> {
    let wide_path = wide(path);
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            wide_path.as_ptr(),
            0,
            std::ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    match status {
        NO_ERROR => Ok(key),
        code => Err(NameError::Registry("creating the rule", code)),
    }
}

fn open(path: &str, access: u32) -> Option<HKEY> {
    let wide_path = wide(path);
    let mut key: HKEY = std::ptr::null_mut();
    let status =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide_path.as_ptr(), 0, access, &mut key) };
    (status == NO_ERROR).then_some(key)
}

fn close(key: HKEY) {
    unsafe { RegCloseKey(key) };
}

fn set_text(key: HKEY, name: &str, value: &str) -> Result<(), NameError> {
    let encoded = wide(value);
    write(key, name, REG_SZ, as_bytes(&encoded))
}

/// A list of namespaces, which the format spells as one string per entry and one empty entry after.
fn set_names(key: HKEY, name: &str, value: &str) -> Result<(), NameError> {
    let mut encoded = wide(value);
    encoded.push(0);
    write(key, name, REG_MULTI_SZ, as_bytes(&encoded))
}

fn set_number(key: HKEY, name: &str, value: u32) -> Result<(), NameError> {
    write(key, name, REG_DWORD, &value.to_ne_bytes())
}

fn write(key: HKEY, name: &str, kind: u32, data: &[u8]) -> Result<(), NameError> {
    let wide_name = wide(name);
    let status = unsafe {
        RegSetValueExW(
            key,
            wide_name.as_ptr(),
            0,
            kind,
            data.as_ptr(),
            data.len() as u32,
        )
    };
    match status {
        NO_ERROR => Ok(()),
        code => Err(NameError::Registry("writing a value of the rule", code)),
    }
}

fn as_bytes(encoded: &[u16]) -> &[u8] {
    // The registry takes a length in bytes and the encoding is UTF-16, so this is the same buffer
    // measured the way the call measures it.
    unsafe { std::slice::from_raw_parts(encoded.as_ptr().cast::<u8>(), encoded.len() * 2) }
}

fn read_text(key: HKEY, name: &str) -> Option<String> {
    let wide_name = wide(name);
    let mut kind = 0u32;
    let mut len = 0u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            std::ptr::null_mut(),
            &mut len,
        )
    };
    if status != NO_ERROR || kind != REG_SZ || len == 0 {
        return None;
    }

    let mut buffer = vec![0u8; len as usize];
    let status = unsafe {
        RegQueryValueExW(
            key,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            buffer.as_mut_ptr(),
            &mut len,
        )
    };
    if status != NO_ERROR {
        return None;
    }

    let units: Vec<u16> = buffer
        .chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

fn subkeys(key: HKEY) -> Vec<String> {
    // The longest a key name may be, plus the terminator. Reused rather than grown, because a name
    // longer than this cannot exist and a call that says otherwise is one to stop reading at.
    let mut buffer = [0u16; 256];
    let mut found = Vec::new();
    for index in 0.. {
        let mut len = buffer.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                buffer.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != NO_ERROR {
            break;
        }
        found.push(String::from_utf16_lossy(&buffer[..len as usize]));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mark travels on the rule, and the sweep is what reads it back. Both are spelled in one
    /// place here so a change to either has to be a change to both.
    #[test]
    fn the_rule_is_marked_with_something_a_later_run_can_find() {
        assert_eq!(MARK, "masqr");
        assert!(RULE.starts_with('{') && RULE.ends_with('}'));
    }

    /// The one call this module makes that Windows does not declare in a header anyone links
    /// against. If the entry point is not there, a policy change would appear to work and quietly
    /// decide nothing for as long as the old answers live — so its presence is checked rather than
    /// hoped for.
    #[test]
    fn the_machine_can_be_told_to_forget_what_it_knows() {
        assert!(
            forget_answers(),
            "dnsapi.dll would not flush the resolver cache"
        );
    }

    /// The enumeration and the reading are calls into Windows written by hand here, and the way a
    /// wrong one fails is an empty answer rather than an error — which in `release` would mean
    /// sweeping nothing and reporting that there was nothing to sweep. So both are exercised
    /// against a key every Windows has and every account can read.
    #[test]
    fn subkeys_and_values_come_back_the_way_windows_returns_them() {
        let services = open(r"SYSTEM\CurrentControlSet\Services", KEY_READ).expect("readable");
        let names = subkeys(services);
        close(services);
        assert!(
            names.len() > 50,
            "a Windows has many services, not {}",
            names.len()
        );
        assert!(
            names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("Dnscache"))
        );

        let dnscache =
            open(r"SYSTEM\CurrentControlSet\Services\Dnscache", KEY_READ).expect("present");
        let shown = read_text(dnscache, "DisplayName");
        // A value of another type is not one this reads: the mark it looks for is text, and
        // returning something for a number would have the sweep compare against nonsense.
        let numeric = read_text(dnscache, "Start");
        close(dnscache);
        assert!(shown.is_some_and(|text| !text.is_empty()));
        assert_eq!(numeric, None);
    }

    /// A canary answered from a cache would prove nothing, so no two are the same.
    #[test]
    fn no_two_canaries_are_the_same() {
        let first = canary();
        assert_ne!(first, canary());
        assert!(first.ends_with(".masqr-check.invalid"));
    }

    /// The list format is one string per entry and an empty entry after it. Written by hand here,
    /// so the shape is worth stating rather than trusting.
    #[test]
    fn a_namespace_list_ends_with_an_empty_entry() {
        let mut encoded = wide(EVERY_NAME);
        encoded.push(0);
        assert_eq!(encoded, vec![u16::from(b'.'), 0, 0]);
    }
}
