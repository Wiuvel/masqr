//! The line side of a destination: the local address that reaches it without passing through the
//! adapter this core owns.
//!
//! What this is for is a resolver the policy says is asked directly while its address is routed into
//! the tunnel for everything else. The application routes the public resolvers' addresses in, so a
//! browser's own secure DNS is carried; the same addresses are often the resolvers the policy names
//! for names that must be answered from the machine's side. A socket bound to the line's address
//! keeps both true. Windows sends with the strong host model: a bound source address restricts the
//! route lookup to routes on the interface that owns it, and the host route into the adapter is not
//! one of them.
//!
//! The interface is chosen the way the stack chooses one, with this core's adapter left out: the
//! longest prefix covering the destination, then the lowest metric — the route's own plus its
//! interface's — among interfaces that are connected. The source address on it is the stack's own
//! choice, asked for with the lookup restricted to that interface.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetBestRoute2, GetIpForwardTable2, GetIpInterfaceEntry, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

use super::socket_address;

/// The local address that reaches `destination` without the adapter `ours`, or `None` when no other
/// interface has a route to it.
///
/// A link-local destination is left alone: it needs its zone to be dialled at all, and the stack's
/// own choice for it is already the line's.
pub fn source_for(ours: u64, destination: IpAddr) -> Option<IpAddr> {
    if is_link_local(destination) {
        return None;
    }
    let family = match destination {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };
    let luid = choose(&routes_to(family, ours, destination))?;

    let interface = NET_LUID_LH { Value: luid };
    let target = socket_address(destination);
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    let status = unsafe {
        GetBestRoute2(
            &interface,
            0,
            std::ptr::null(),
            &target,
            0,
            &mut route,
            &mut source,
        )
    };
    if status != NO_ERROR {
        return None;
    }
    address_of(&source).filter(|address| !address.is_unspecified())
}

/// One route that could carry a packet to the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Candidate {
    luid: u64,
    prefix: u8,
    /// The route's metric plus its interface's, which is the number Windows compares.
    metric: u32,
}

/// The interface the stack would pick among these: longest prefix, then lowest metric.
fn choose(candidates: &[Candidate]) -> Option<u64> {
    candidates
        .iter()
        .max_by(|a, b| {
            a.prefix
                .cmp(&b.prefix)
                .then_with(|| b.metric.cmp(&a.metric))
        })
        .map(|candidate| candidate.luid)
}

/// Every route in the table that covers `destination`, on a connected interface other than `ours`.
fn routes_to(family: u16, ours: u64, destination: IpAddr) -> Vec<Candidate> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(family, &mut table) } != NO_ERROR || table.is_null() {
        return Vec::new();
    }
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };

    // The table has a row per route and this core alone installs hundreds, so an interface's metric
    // is read once per lookup rather than once per row.
    let mut interfaces: HashMap<u64, Option<u32>> = HashMap::new();
    let mut candidates = Vec::new();
    for row in rows {
        let luid = unsafe { row.InterfaceLuid.Value };
        if luid == ours {
            continue;
        }
        let Some(prefix) = address_of(&row.DestinationPrefix.Prefix) else {
            continue;
        };
        let length = row.DestinationPrefix.PrefixLength;
        if !covers(prefix, length, destination) {
            continue;
        }
        let Some(interface) = *interfaces
            .entry(luid)
            .or_insert_with(|| interface_metric(family, luid))
        else {
            continue;
        };
        candidates.push(Candidate {
            luid,
            prefix: length,
            metric: row.Metric.saturating_add(interface),
        });
    }
    unsafe { FreeMibTable(table.cast()) };
    candidates
}

/// An interface's metric, or `None` when it is not connected — a route on an interface with no link
/// is a row in a table, not a way out.
fn interface_metric(family: u16, luid: u64) -> Option<u32> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.Family = family;
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    if unsafe { GetIpInterfaceEntry(&mut row) } != NO_ERROR || !row.Connected {
        return None;
    }
    Some(row.Metric)
}

/// Whether a prefix covers an address of the same family.
fn covers(prefix: IpAddr, length: u8, destination: IpAddr) -> bool {
    match (prefix, destination) {
        (IpAddr::V4(prefix), IpAddr::V4(destination)) => {
            let length = u32::from(length.min(32));
            length == 0 || {
                let mask = u32::MAX << (32 - length);
                u32::from(prefix) & mask == u32::from(destination) & mask
            }
        }
        (IpAddr::V6(prefix), IpAddr::V6(destination)) => {
            let length = u32::from(length.min(128));
            length == 0 || {
                let mask = u128::MAX << (128 - length);
                u128::from(prefix) & mask == u128::from(destination) & mask
            }
        }
        _ => false,
    }
}

/// An address out of the shape IP Helper returns, or `None` for a family this does not read.
fn address_of(raw: &SOCKADDR_INET) -> Option<IpAddr> {
    match unsafe { raw.si_family } {
        AF_INET => {
            // Network byte order, which on this platform means the octets as they are stored.
            let octets = unsafe { raw.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(unsafe {
            raw.Ipv6.sin6_addr.u.Byte
        }))),
        _ => None,
    }
}

fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(written: &str) -> IpAddr {
        written.parse().expect("a literal address")
    }

    #[test]
    fn a_prefix_covers_what_it_says_and_nothing_else() {
        assert!(
            covers(ip("0.0.0.0"), 0, ip("8.8.8.8")),
            "a default route covers everything"
        );
        assert!(covers(ip("8.8.8.0"), 24, ip("8.8.8.8")));
        assert!(covers(ip("8.8.8.8"), 32, ip("8.8.8.8")));
        assert!(!covers(ip("8.8.4.0"), 24, ip("8.8.8.8")));
        assert!(covers(ip("2001:4860::"), 32, ip("2001:4860:4860::8888")));
        assert!(!covers(ip("2606:4700::"), 32, ip("2001:4860:4860::8888")));
        assert!(!covers(ip("::"), 0, ip("8.8.8.8")), "never across families");
    }

    /// The order the stack uses. A shorter prefix never wins on metric: a host route into a VPN
    /// beats the default route on the line however cheap the line is, and that is the route a
    /// resolver on that VPN has to be asked by.
    #[test]
    fn the_longest_prefix_wins_and_then_the_lowest_metric() {
        let line = Candidate {
            luid: 1,
            prefix: 0,
            metric: 25,
        };
        let vpn = Candidate {
            luid: 2,
            prefix: 24,
            metric: 5000,
        };
        let backup = Candidate {
            luid: 3,
            prefix: 0,
            metric: 60,
        };
        assert_eq!(choose(&[line, vpn, backup]), Some(2));
        assert_eq!(choose(&[backup, line]), Some(1));
        assert_eq!(choose(&[]), None);
    }

    #[test]
    fn a_link_local_destination_is_not_rebound() {
        assert!(is_link_local(ip("169.254.1.1")));
        assert!(is_link_local(ip("fe80::1")));
        assert!(!is_link_local(ip("8.8.8.8")));
        assert!(!is_link_local(ip("2001:4860:4860::8888")));
        assert_eq!(source_for(0, ip("fe80::1")), None);
    }

    /// Against Windows rather than a description of it. The loopback route is on every machine and
    /// on no adapter of this core's, so the lookup has one right answer here: the loopback address
    /// itself. A wrong table walk or a misread address comes back as something else, or as nothing.
    #[test]
    fn windows_answers_the_loopback_route_with_the_loopback_address() {
        assert_eq!(source_for(0, ip("127.0.0.1")), Some(ip("127.0.0.1")));
    }
}
