//! The Wintun adapter: the side of the tunnel the operating system sees.
//!
//! It carries the address Cloudflare assigned and nothing else. Only traffic meant for the tunnel
//! is routed here, by host routes this module installs, so a packet arriving from Windows already
//! carries the right source address and needs no rewriting on the way out — a network stack on this
//! side would exist only to undo work Windows already did. See `docs/design/decisions.md`.
//!
//! The adapter and its routes are owned: dropping the adapter removes it from Windows and takes the
//! routes with it. Nothing survives the process to be swept up later.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND,
    ERROR_OBJECT_ALREADY_EXISTS, GetLastError, HANDLE, NO_ERROR, WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, GetIpInterfaceEntry,
    InitializeIpForwardEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IpDadStatePreferred, SOCKADDR_INET,
};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};

pub mod outside;
pub mod sys;

use sys::{AdapterHandle, SessionHandle, Wintun, wide};

/// The read thread has nothing else to do until a packet arrives or it is asked to stop.
const WAIT_FOREVER: u32 = u32::MAX;

/// The ring the driver and this process share, per direction. Wintun requires a power of two
/// between 128 KiB and 64 MiB; four megabytes is what a saturated link needs to absorb a scheduling
/// hiccup without the driver dropping packets, and it is committed once at start.
pub const RING_CAPACITY: u32 = 0x40_0000;

/// How long an adapter name still held by an instance on its way out is waited for.
///
/// Wintun ties the adapter to the process that created it: when that process ends Windows removes
/// the device, but the removal is asynchronous and the name stays taken until it finishes. A core
/// started the moment its predecessor exits therefore meets its own leftover, so this waits for a
/// removal Windows is already performing rather than for anything this process could do to help.
const NAME_RELEASE_BUDGET: Duration = Duration::from_secs(8);

/// How often the name is asked for again while it is being waited for.
const NAME_RELEASE_POLL: Duration = Duration::from_millis(250);

#[derive(Debug, thiserror::Error)]
/// Why the adapter, its addresses or its routes could not be made to say what was asked.
pub enum TunError {
    #[error("loading wintun: {0}")]
    Load(#[from] sys::LoadError),
    #[error("the adapter could not be created — this needs to run elevated: {0}")]
    Create(std::io::Error),
    #[error("the adapter name was still held by an instance on its way out after {0:?}")]
    NameHeld(Duration),
    #[error("the adapter session could not be started: {0}")]
    Session(std::io::Error),
    #[error("assigning {0} to the adapter failed with error {1}")]
    Address(IpAddr, u32),
    #[error("routing {0}/{1} into the tunnel failed with error {2}")]
    Route(IpAddr, u8, u32),
    #[error("removing the route for {0}/{1} failed with error {2}")]
    RouteRemoval(IpAddr, u8, u32),
    #[error("setting the adapter MTU failed with error {0}")]
    Mtu(u32),
    #[error("a packet of {0} bytes could not be written to the adapter: {1}")]
    Send(usize, std::io::Error),
}

/// A live Wintun adapter.
pub struct Adapter {
    wintun: Arc<Wintun>,
    handle: AdapterHandle,
    luid: u64,
}

// The handle is a driver object with no thread affinity; Wintun's own documentation only
// constrains sessions, and those are held by one reader and one writer (see `Session`).
unsafe impl Send for Adapter {}
unsafe impl Sync for Adapter {}

impl Adapter {
    /// Create the adapter. `name` is what Windows lists; `tunnel_type` is the description beside
    /// it, and is also what a sweep for a stale adapter looks for.
    pub fn create(wintun: Arc<Wintun>, name: &str, tunnel_type: &str) -> Result<Self, TunError> {
        let guid = adapter_guid(name);
        let wide_name = wide(name);
        let wide_type = wide(tunnel_type);
        let handle = create_waiting(
            || {
                let handle = unsafe {
                    (wintun.create_adapter)(wide_name.as_ptr(), wide_type.as_ptr(), &guid)
                };
                match handle.is_null() {
                    true => Err(std::io::Error::last_os_error()),
                    false => Ok(handle),
                }
            },
            NAME_RELEASE_BUDGET,
            NAME_RELEASE_POLL,
        )?;

        let mut luid = 0u64;
        unsafe { (wintun.get_adapter_luid)(handle, &mut luid) };
        Ok(Self {
            wintun,
            handle,
            luid,
        })
    }

    /// Which interface this is, as Windows names it in its own tables.
    ///
    /// Held out so that something watching the machine's interfaces can tell a change made by this
    /// core from a change made to the line underneath it. The two are indistinguishable otherwise,
    /// and this core changes its own adapter constantly — every route it installs is one.
    pub fn luid(&self) -> u64 {
        self.luid
    }

    /// The version of the driver actually running, as `major.minor`.
    pub fn driver_version(&self) -> String {
        let packed = unsafe { (self.wintun.get_running_driver_version)() };
        format!("{}.{}", packed >> 16, packed & 0xffff)
    }

    /// Give the adapter an address. This is the address Cloudflare assigned, put on the interface
    /// unchanged so that Windows itself sets it as the source of every packet routed here.
    pub fn add_address(&self, address: IpAddr, prefix: u8) -> Result<(), TunError> {
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid = NET_LUID_LH { Value: self.luid };
        row.Address = socket_address(address);
        row.OnLinkPrefixLength = prefix;
        // Without this the address spends its first seconds in duplicate-address detection, and a
        // socket bound during that window is refused. There is no neighbour on a point-to-point
        // tunnel to detect a duplicate against.
        row.DadState = IpDadStatePreferred;

        let status = unsafe { CreateUnicastIpAddressEntry(&row) };
        if status != NO_ERROR {
            return Err(TunError::Address(address, status));
        }
        Ok(())
    }

    /// Set the MTU for one address family.
    pub fn set_mtu(&self, family: Family, mtu: u32) -> Result<(), TunError> {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        row.Family = family.af();
        row.InterfaceLuid = NET_LUID_LH { Value: self.luid };
        let status = unsafe { GetIpInterfaceEntry(&mut row) };
        if status != NO_ERROR {
            return Err(TunError::Mtu(status));
        }

        row.NlMtu = mtu;
        // IP Helper rejects the row it just handed out unless this is cleared first — a documented
        // quirk of `SetIpInterfaceEntry`, not a value that means anything here.
        row.SitePrefixLength = 0;

        let status = unsafe { SetIpInterfaceEntry(&mut row) };
        if status != NO_ERROR {
            return Err(TunError::Mtu(status));
        }
        Ok(())
    }

    /// Route a prefix into the tunnel.
    ///
    /// On-link, with no next hop: the adapter is one end of a point-to-point link, so there is no
    /// gateway to send anything to. A host route beats the default route by being longer, which is
    /// what keeps everything else off this interface.
    pub fn add_route(&self, destination: IpAddr, prefix: u8) -> Result<(), TunError> {
        let row = self.forward_row(destination, prefix);
        let status = unsafe { CreateIpForwardEntry2(&row) };
        // A row that is already there is the state being asked for. It happens after a process that
        // did not get to clean up, and reporting it as a failure would make one leftover row enough
        // to stop the whole set from being installed.
        if status != NO_ERROR && status != ERROR_OBJECT_ALREADY_EXISTS {
            return Err(TunError::Route(destination, prefix, status));
        }
        Ok(())
    }

    /// Stop routing a prefix into the tunnel. Whatever was reaching it through here goes back to
    /// whichever route is next longest, which is normally the line.
    pub fn remove_route(&self, destination: IpAddr, prefix: u8) -> Result<(), TunError> {
        let row = self.forward_row(destination, prefix);
        let status = unsafe { DeleteIpForwardEntry2(&row) };
        // A row that is already gone is likewise the state being asked for: Windows removes every
        // route on an interface when the interface goes, so this is the ordinary reading after one
        // has been replaced underneath.
        if status != NO_ERROR && status != ERROR_NOT_FOUND {
            return Err(TunError::RouteRemoval(destination, prefix, status));
        }
        Ok(())
    }

    /// The row that names one route on this adapter. Adding and removing take the same one, and
    /// building it in one place is what keeps them describing the same route.
    fn forward_row(&self, destination: IpAddr, prefix: u8) -> MIB_IPFORWARD_ROW2 {
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = NET_LUID_LH { Value: self.luid };
        row.DestinationPrefix.Prefix = socket_address(destination);
        row.DestinationPrefix.PrefixLength = prefix;
        row.NextHop = socket_address(match destination {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        });
        row.Metric = 0;
        row
    }

    /// Start moving packets. Wintun allows one session per adapter.
    pub fn start(&self) -> Result<Session, TunError> {
        let handle = unsafe { (self.wintun.start_session)(self.handle, RING_CAPACITY) };
        if handle.is_null() {
            return Err(TunError::Session(std::io::Error::last_os_error()));
        }
        let read_event = unsafe { (self.wintun.get_read_wait_event)(handle) };
        // Manual reset, unsignalled, unnamed: once set it stays set, so a reader that checks it
        // late still sees it.
        let quit = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if quit.is_null() {
            unsafe { (self.wintun.end_session)(handle) };
            return Err(TunError::Session(std::io::Error::last_os_error()));
        }
        Ok(Session {
            wintun: Arc::clone(&self.wintun),
            handle,
            read_event,
            quit,
            ended: AtomicBool::new(false),
        })
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        // This removes the adapter from Windows, and its addresses and routes go with it.
        unsafe { (self.wintun.close_adapter)(self.handle) };
    }
}

/// The adapter's identity, derived from its name so that it is the same every run.
///
/// Wintun's default is a fresh random GUID per adapter. Windows keys a network profile to it, so
/// every run produced another "unidentified network" and left the previous device behind: visible
/// as duplicate adapters, one of them dead.
///
/// The formula is `md5("wintun" + name)` read as a GUID, the same one `sing-tun` uses. The
/// application sweeps leftover tunnel adapters by recomputing exactly this, so one sweep covers
/// both cores.
/// Ask for the adapter until the name is free.
///
/// Only `ERROR_ALREADY_EXISTS` is waited on, and only for as long as a device removal takes. Every
/// other refusal returns at once: an access denial does not improve by being asked again, and
/// waiting it out would turn a message about elevation into a delayed one saying the same thing.
fn create_waiting<T>(
    make: impl Fn() -> Result<T, std::io::Error>,
    budget: Duration,
    poll: Duration,
) -> Result<T, TunError> {
    let deadline = Instant::now() + budget;
    let mut waiting = false;
    loop {
        let problem = match make() {
            Ok(made) => return Ok(made),
            Err(problem) => problem,
        };
        if problem.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(TunError::Create(problem));
        }
        if Instant::now() + poll >= deadline {
            return Err(TunError::NameHeld(budget));
        }
        if !waiting {
            waiting = true;
            notice!(
                "adapter",
                "the name is held by an instance on its way out; waiting for its removal"
            );
        }
        std::thread::sleep(poll);
    }
}

fn adapter_guid(name: &str) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(b"wintun");
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

/// One prefix routed into the tunnel.
pub type Prefix = (IpAddr, u8);

/// Read one prefix as it is written: `address`, or `address/length`.
///
/// A bare address is one host, which is what a target usually is.
pub fn parse_prefix(written: &str) -> Result<Prefix, String> {
    let (address, length) = match written.split_once('/') {
        Some((address, length)) => (address, Some(length)),
        None => (written, None),
    };
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("`{written}` is not an address"))?;
    let whole = if address.is_ipv4() { 32 } else { 128 };
    let length = match length {
        Some(length) => length
            .parse::<u8>()
            .map_err(|_| format!("`{written}` has no prefix length after the slash"))?,
        None => whole,
    };
    if length > whole {
        return Err(format!(
            "`{written}` is longer than its address family allows"
        ));
    }
    Ok((address, length))
}

/// What changed when a new set of prefixes was applied.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Change {
    pub added: Vec<Prefix>,
    pub removed: Vec<Prefix>,
}

impl Change {
    /// Whether anything moved at all. A set applied twice is not an event.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// The two operations [`Routes::apply`] needs of a routing table.
///
/// A trait with exactly one real implementation, and the reason is the bookkeeping in `apply`: the
/// installed set has to end up naming precisely the rows that moved, including when some of them
/// were refused. That is a property no amount of care establishes on its own — it needs a table
/// that can be told to refuse a particular row on demand, which a real adapter cannot be.
pub trait RouteTable {
    /// Route one prefix into the tunnel. A row that is already there is the state being asked for.
    fn add(&self, destination: IpAddr, prefix: u8) -> Result<(), TunError>;
    /// Take one prefix back out. A row already gone is the state being asked for.
    fn remove(&self, destination: IpAddr, prefix: u8) -> Result<(), TunError>;
}

impl RouteTable for Adapter {
    fn add(&self, destination: IpAddr, prefix: u8) -> Result<(), TunError> {
        self.add_route(destination, prefix)
    }

    fn remove(&self, destination: IpAddr, prefix: u8) -> Result<(), TunError> {
        self.remove_route(destination, prefix)
    }
}

/// The prefixes currently routed into the tunnel.
///
/// All routing means here. What goes through the tunnel is decided by the operating system's
/// routing table, not by anything in this process, so a set of prefixes and the ability to change
/// it in place is everything a routing engine would have added.
#[derive(Debug, Default)]
pub struct Routes {
    installed: BTreeSet<Prefix>,
}

impl Routes {
    /// Make the installed set match `wanted`, and say what moved.
    ///
    /// Removals go first: a prefix being replaced by a longer or shorter one covering the same
    /// addresses should not have two rows in the table at once, however briefly.
    ///
    /// One row Windows refuses does not stop the rest: every prefix is attempted, the set is
    /// updated to name exactly the rows that moved, and the first refusal is returned after all of
    /// them. The next call then sees the difference genuinely left.
    ///
    /// Written out rather than left to `?` because an early return corrupts the set both ways.
    /// After a successful removal it would claim a row that is gone and never put it back; after a
    /// successful addition it would deny a row that exists and retry it forever.
    pub fn apply(
        &mut self,
        table: &impl RouteTable,
        wanted: &BTreeSet<Prefix>,
    ) -> Result<Change, TunError> {
        let mut change = Change::default();
        let mut refused = None;

        let going: Vec<Prefix> = self.installed.difference(wanted).copied().collect();
        for (destination, prefix) in going {
            match table.remove(destination, prefix) {
                Ok(()) => {
                    self.installed.remove(&(destination, prefix));
                    change.removed.push((destination, prefix));
                }
                Err(problem) => drop(refused.get_or_insert(problem)),
            }
        }

        let coming: Vec<Prefix> = wanted.difference(&self.installed).copied().collect();
        for (destination, prefix) in coming {
            match table.add(destination, prefix) {
                Ok(()) => {
                    self.installed.insert((destination, prefix));
                    change.added.push((destination, prefix));
                }
                Err(problem) => drop(refused.get_or_insert(problem)),
            }
        }

        match refused {
            Some(problem) => Err(problem),
            None => Ok(change),
        }
    }

    /// What is routed into the tunnel right now.
    pub fn installed(&self) -> &BTreeSet<Prefix> {
        &self.installed
    }
}

/// Which address family a call applies to. IP Helper takes a family on rows that would otherwise
/// be ambiguous, and the two constants are easy to pass the wrong way round as bare numbers.
#[derive(Debug, Clone, Copy)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn af(self) -> u16 {
        match self {
            Family::V4 => AF_INET,
            Family::V6 => AF_INET6,
        }
    }
}

/// A live session: packets read from Windows, packets written back to it.
///
/// Wintun permits one reader and one writer at a time. Both ends are handed out separately for
/// exactly that reason — the reader goes to a blocking thread, the writer to the task that drains
/// the tunnel — so the rule is expressed in the types rather than left to a comment.
pub struct Session {
    wintun: Arc<Wintun>,
    handle: SessionHandle,
    read_event: HANDLE,
    /// Set to ask the reader to stop, and never reset.
    ///
    /// Stopping a reader by ending its session crashes. Wintun signals readability through an
    /// event and ending the session does make that wait return, but ending a session while another
    /// thread is inside it is what Wintun forbids — and a reader mid-`receive` rather than
    /// mid-`wait` is inside it. Measured: fifty stops under traffic, fifty access violations. So
    /// the reader waits on this event too, and stopping is setting it, which touches nothing the
    /// driver owns.
    quit: HANDLE,
    /// Whether the session has already been ended.
    ended: AtomicBool,
}

unsafe impl Send for Session {}
unsafe impl Sync for Session {}

impl Session {
    /// Split into the two halves the rule allows, sharing ownership of the session itself.
    pub fn split(self) -> (Reader, Writer) {
        let shared = Arc::new(self);
        (
            Reader {
                session: Arc::clone(&shared),
            },
            Writer { session: shared },
        )
    }
}

impl Session {
    /// Ask the reader to stop, without touching anything the driver owns.
    ///
    /// The first half of an orderly shutdown, and the half that has to come first: once this has
    /// been set and the reader has been seen to leave, nothing is inside the session and it can be
    /// ended.
    pub fn stop_reading(&self) {
        unsafe { SetEvent(self.quit) };
    }

    /// End the session, releasing the ring.
    ///
    /// Called once, whichever way it is reached, and only when no reader is inside it. Wintun
    /// requires a session to be ended before its adapter is closed; it equally requires that
    /// nothing is using the session when it ends, and the two together are what make the order
    /// here — stop, wait, end, close — the only correct one.
    pub fn close(&self) {
        if !self.ended.swap(true, Ordering::AcqRel) {
            unsafe { (self.wintun.end_session)(self.handle) };
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
        unsafe { CloseHandle(self.quit) };
    }
}

/// The receiving half. Blocking by design: Wintun signals readability through an event, and a
/// dedicated thread waiting on it is both the documented way to use it and the cheapest.
pub struct Reader {
    session: Arc<Session>,
}

impl Reader {
    /// The next packet from Windows, blocking until there is one.
    ///
    /// `None` means the reader was asked to stop, or the session failed. In the first case it
    /// returns having touched nothing the driver owns, so the session can then be ended safely.
    pub fn recv(&self) -> Option<Vec<u8>> {
        loop {
            let mut size = 0u32;
            let packet =
                unsafe { (self.session.wintun.receive_packet)(self.session.handle, &mut size) };
            if !packet.is_null() {
                let copied = unsafe { std::slice::from_raw_parts(packet, size as usize) }.to_vec();
                // The ring slot is the driver's, not ours: it has to go back before the next read,
                // or the ring fills with packets nobody released.
                unsafe {
                    (self.session.wintun.release_receive_packet)(self.session.handle, packet)
                };
                return Some(copied);
            }
            if unsafe { GetLastError() } != ERROR_NO_MORE_ITEMS {
                return None;
            }
            // Either a packet arrived or the session is being taken down. Anything other than the
            // first is a reason to leave without asking the driver for anything else.
            let waiting = [self.session.read_event, self.session.quit];
            let woke = unsafe { WaitForMultipleObjects(2, waiting.as_ptr(), 0, WAIT_FOREVER) };
            if woke != WAIT_OBJECT_0 {
                return None;
            }
        }
    }
}

/// The sending half: packets from the tunnel, handed to Windows.
pub struct Writer {
    session: Arc<Session>,
}

impl Writer {
    /// Ask the reader to stop. Both halves share the session, and this is the half a shutdown can
    /// reach — the other one is inside a blocking wait.
    pub fn stop_reading(&self) {
        self.session.stop_reading();
    }

    /// End the session this half belongs to.
    ///
    /// Only once the reader has been seen to leave: ending a session while a thread is inside it
    /// is what Wintun forbids, and what it does instead of refusing is take the process down.
    pub fn close(&self) {
        self.session.close();
    }

    /// Write one packet to the adapter.
    ///
    /// The buffer comes from the driver's ring and is filled in place, so the packet is copied
    /// once rather than twice.
    pub fn send(&self, packet: &[u8]) -> Result<(), TunError> {
        let slot = unsafe {
            (self.session.wintun.allocate_send_packet)(self.session.handle, packet.len() as u32)
        };
        if slot.is_null() {
            return Err(TunError::Send(
                packet.len(),
                std::io::Error::last_os_error(),
            ));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), slot, packet.len());
            (self.session.wintun.send_packet)(self.session.handle, slot);
        }
        Ok(())
    }
}

/// An `IpAddr` in the shape IP Helper takes.
fn socket_address(address: IpAddr) -> SOCKADDR_INET {
    let mut out: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match address {
        IpAddr::V4(v4) => {
            out.Ipv4.sin_family = AF_INET;
            // Network byte order, which on this platform means the octets as written.
            out.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            out.Ipv6.sin6_family = AF_INET6;
            out.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    use super::*;

    /// The adapter identity is shared with the application, which recomputes it to recognise a
    /// leftover adapter as ours. A change here that nobody notices would leave those behind, so the
    /// value is pinned rather than merely recomputed by the same formula twice.
    ///
    /// Written the way Windows displays a GUID: the first three fields little-endian, which is
    /// simply how the sixteen bytes are laid out in memory.
    #[test]
    fn the_adapter_identity_is_the_one_the_application_expects() {
        let guid = adapter_guid("masqr");
        let tail: String = guid[10..16].iter().map(|b| format!("{b:02X}")).collect();
        let shown = format!(
            "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{tail}}}",
            guid[3],
            guid[2],
            guid[1],
            guid[0],
            guid[5],
            guid[4],
            guid[7],
            guid[6],
            guid[8],
            guid[9]
        );
        assert_eq!(shown, "{90D868D8-6AD7-F602-7322-B275D3ECB2E4}");
    }

    /// A table that refuses whichever rows it is told to, so the bookkeeping can be checked
    /// against a refusal rather than only against a run where everything worked.
    #[derive(Default)]
    struct Bench {
        rows: std::cell::RefCell<BTreeSet<Prefix>>,
        refuse: BTreeSet<Prefix>,
    }

    impl RouteTable for Bench {
        fn add(&self, destination: IpAddr, prefix: u8) -> Result<(), TunError> {
            if self.refuse.contains(&(destination, prefix)) {
                return Err(TunError::Route(destination, prefix, 1));
            }
            self.rows.borrow_mut().insert((destination, prefix));
            Ok(())
        }

        fn remove(&self, destination: IpAddr, prefix: u8) -> Result<(), TunError> {
            if self.refuse.contains(&(destination, prefix)) {
                return Err(TunError::RouteRemoval(destination, prefix, 1));
            }
            self.rows.borrow_mut().remove(&(destination, prefix));
            Ok(())
        }
    }

    fn set(written: &[&str]) -> BTreeSet<Prefix> {
        written
            .iter()
            .map(|one| parse_prefix(one).unwrap())
            .collect()
    }

    /// The ordinary case, stated so the ones below have something to differ from.
    #[test]
    fn applying_a_set_installs_exactly_it() {
        let bench = Bench::default();
        let mut routes = Routes::default();

        let change = routes
            .apply(&bench, &set(&["1.1.1.1/32", "8.8.8.8/32"]))
            .unwrap();
        assert_eq!(change.added.len(), 2);
        assert_eq!(*routes.installed(), *bench.rows.borrow());

        // The same set again is not an event, and asks Windows for nothing.
        assert!(
            routes
                .apply(&bench, &set(&["1.1.1.1/32", "8.8.8.8/32"]))
                .unwrap()
                .is_empty()
        );
    }

    /// One row Windows will not add must not cost the others. The set has to deny only the row
    /// that is really absent — claiming the others too would have every later call add them again,
    /// and each of those would be refused as already there.
    #[test]
    fn a_refused_addition_does_not_take_the_rest_with_it() {
        let bench = Bench {
            refuse: set(&["9.9.9.9/32"]),
            ..Bench::default()
        };
        let mut routes = Routes::default();

        assert!(
            routes
                .apply(&bench, &set(&["1.1.1.1/32", "9.9.9.9/32", "8.8.8.8/32"]))
                .is_err()
        );
        assert_eq!(*routes.installed(), set(&["1.1.1.1/32", "8.8.8.8/32"]));
        assert_eq!(
            *routes.installed(),
            *bench.rows.borrow(),
            "the set describes the table"
        );
    }

    /// And the mirror: a row that could not be removed stays in the set, so the next call tries
    /// again. Dropping it would leave a row routed into a tunnel with nothing tracking it.
    #[test]
    fn a_refused_removal_stays_in_the_set_to_be_tried_again() {
        let bench = Bench {
            refuse: set(&["9.9.9.9/32"]),
            ..Bench::default()
        };
        let mut routes = Routes::default();
        bench
            .rows
            .borrow_mut()
            .extend(set(&["1.1.1.1/32", "9.9.9.9/32"]));
        routes.installed = set(&["1.1.1.1/32", "9.9.9.9/32"]);

        assert!(routes.apply(&bench, &BTreeSet::new()).is_err());
        assert_eq!(*routes.installed(), set(&["9.9.9.9/32"]));
        assert_eq!(
            *routes.installed(),
            *bench.rows.borrow(),
            "the set describes the table"
        );
    }

    /// The name a predecessor still holds is waited for rather than failed over. Windows removes
    /// that adapter on its own once the process that made it has gone, and a core restarted at the
    /// speed the application restarts it arrives before the removal has finished.
    #[test]
    fn a_name_still_held_is_waited_for() {
        let tries = Cell::new(0);
        let made = create_waiting(
            || {
                tries.set(tries.get() + 1);
                match tries.get() < 3 {
                    true => Err(std::io::Error::from_raw_os_error(
                        ERROR_ALREADY_EXISTS as i32,
                    )),
                    false => Ok(()),
                }
            },
            Duration::from_millis(500),
            Duration::from_millis(1),
        );

        assert!(made.is_ok());
        assert_eq!(tries.get(), 3);
    }

    /// Any other refusal is answered immediately, because nothing about it changes by waiting.
    #[test]
    fn any_other_refusal_is_not_waited_out() {
        let tries = Cell::new(0);
        let made = create_waiting(
            || -> Result<(), std::io::Error> {
                tries.set(tries.get() + 1);
                Err(std::io::Error::from_raw_os_error(
                    ERROR_ACCESS_DENIED as i32,
                ))
            },
            Duration::from_secs(30),
            Duration::from_millis(1),
        );

        assert!(matches!(made, Err(TunError::Create(_))));
        assert_eq!(tries.get(), 1, "asked once, not once per poll");
    }

    /// And the waiting ends. A name never released is a leftover this process cannot remove, and
    /// saying so is what lets whoever started the core act on it instead of watching it hang.
    #[test]
    fn waiting_for_a_name_that_is_never_released_ends() {
        let made = create_waiting(
            || -> Result<(), std::io::Error> {
                Err(std::io::Error::from_raw_os_error(
                    ERROR_ALREADY_EXISTS as i32,
                ))
            },
            Duration::from_millis(20),
            Duration::from_millis(2),
        );

        assert!(matches!(made, Err(TunError::NameHeld(_))));
    }

    /// Targets come from a person or from the application, so the shapes both write matter.
    #[test]
    fn a_prefix_is_read_the_way_it_is_written() {
        assert_eq!(
            parse_prefix("1.1.1.1").unwrap(),
            ("1.1.1.1".parse().unwrap(), 32)
        );
        assert_eq!(
            parse_prefix("104.16.0.0/16").unwrap(),
            ("104.16.0.0".parse().unwrap(), 16)
        );
        assert_eq!(
            parse_prefix("2606:4700::").unwrap(),
            ("2606:4700::".parse().unwrap(), 128)
        );
        assert!(parse_prefix("1.1.1.1/33").is_err());
        assert!(parse_prefix("nonsense").is_err());
    }
}
