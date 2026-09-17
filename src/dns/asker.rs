//! Which program asked.
//!
//! A query arrives from a port on loopback, and Windows knows which process owns that port. This
//! does **not** allow routing by process — a routing table decides by destination alone. It allows
//! a policy rule of the form *when this program asks, the answer becomes a route*; the program's
//! traffic then follows that route like any other.
//!
//! The failure mode is over-inclusion: another program asking the same name gets the same route,
//! which is what a rule about the name alone would have done anyway. Keeping one program out while
//! others are let in cannot be built this way and is not attempted.
//!
//! Two caches. The port table is re-read on a short timer because it changes constantly and each
//! read costs a pair of system calls; a process image path never changes, so it is held until the
//! table stops mentioning the process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

/// How long a reading of the port table is reused.
///
/// One reading per query would put two system calls and an allocation in front of every name the
/// machine looks up. A second is short next to how long a program keeps a socket open and long next
/// to how fast queries arrive.
const TABLE_TTL: Duration = Duration::from_millis(1000);

/// The most process images remembered. A machine does not have thousands of distinct programs
/// asking questions, and a bound is what keeps a machine that does from growing this without end.
const MAX_IMAGES: usize = 512;

/// A program, in the two forms a policy may name it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// The executable's full path, lowercase.
    pub path: String,
    /// Its file name alone, lowercase.
    pub name: String,
}

impl Program {
    fn from_path(path: String) -> Self {
        let path = path.to_ascii_lowercase();
        let name = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_owned();
        Self { path, name }
    }
}

/// One reading of a protocol's port table: every loopback port, and the process that owns it.
type ReadTable = fn() -> Option<HashMap<u16, u32>>;

/// Where a query came from, and over which protocol.
///
/// The protocol is carried because the answer depends on it: Windows keeps a table of port owners
/// per protocol, and a TCP port looked up in the UDP table is not merely absent from it — it can
/// name whichever unrelated program holds that number on the other protocol.
#[derive(Debug, Clone, Copy)]
pub enum From {
    Udp(std::net::SocketAddr),
    Tcp(std::net::SocketAddr),
}

impl From {
    fn port(self) -> u16 {
        match self {
            From::Udp(address) | From::Tcp(address) => address.port(),
        }
    }
}

/// Who is asking, looked up by the port a query came from.
#[derive(Debug, Default)]
pub struct Askers {
    udp: Mutex<Option<Snapshot>>,
    tcp: Mutex<Option<Snapshot>>,
    images: Mutex<HashMap<u32, Arc<Program>>>,
}

#[derive(Debug)]
struct Snapshot {
    at: Instant,
    /// Local port → owning process. Only loopback rows are kept: a query to this core comes from
    /// this machine, and every other row is a port this will never be asked about.
    owners: HashMap<u16, u32>,
}

impl Askers {
    /// An empty set of readings. The port tables are read on the first question, not before.
    pub fn new() -> Self {
        Self::default()
    }

    /// The program that owns the loopback port a query came from, if it can be established.
    ///
    /// `None` is an ordinary answer, not an error: a socket closed between sending and this lookup,
    /// a process that ended, or a program this one may not open. A policy treats an unknown asker
    /// as matching no program-conditional rule, which is the conservative reading.
    pub fn of_port(&self, from: From, now: Instant) -> Option<Arc<Program>> {
        let pid = match from {
            From::Udp(_) => Self::owner_of(&self.udp, read_udp_owners, from.port(), now),
            From::Tcp(_) => Self::owner_of(&self.tcp, read_tcp_owners, from.port(), now),
        }?;

        if let Some(known) = self.locked_images().get(&pid) {
            return Some(Arc::clone(known));
        }

        let program = Arc::new(Program::from_path(image_of(pid)?));
        let mut images = self.locked_images();
        // A process identifier is reused, and quickly. Keeping one for the rest of the session
        // means attributing a later program's questions to one that has since ended, so the bound
        // is reached by forgetting everything rather than by keeping the oldest: the next question
        // each live program asks puts it straight back, at the cost of one lookup.
        if images.len() >= MAX_IMAGES {
            images.clear();
        }
        images.insert(pid, Arc::clone(&program));
        Some(program)
    }

    fn owner_of(
        held: &Mutex<Option<Snapshot>>,
        read: ReadTable,
        port: u16,
        now: Instant,
    ) -> Option<u32> {
        let mut held = held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fresh = held
            .as_ref()
            .is_some_and(|snapshot| now.duration_since(snapshot.at) < TABLE_TTL);
        if !fresh {
            *held = Some(Snapshot {
                at: now,
                owners: read()?,
            });
        }
        held.as_ref()?.owners.get(&port).copied()
    }

    fn locked_images(&self) -> std::sync::MutexGuard<'_, HashMap<u32, Arc<Program>>> {
        self.images
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Every loopback UDP port and the process that owns it.
///
/// Read twice on purpose: once to be told how large the table is, once to read it. Windows offers
/// no other shape, and the size can change between the two calls — which is why a second failure is
/// an answer of `None` rather than a retry loop.
fn read_udp_owners() -> Option<HashMap<u16, u32>> {
    let mut size = 0u32;
    // The first call is expected to fail with "insufficient buffer"; what is wanted from it is the
    // size it writes.
    unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            u32::from(AF_INET),
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if size == 0 {
        return None;
    }

    // Allocated as `u32` so the buffer is aligned for the structures Windows writes into it; a
    // `Vec<u8>` carries no such guarantee.
    let words = (size as usize).div_ceil(4);
    let mut buffer = vec![0u32; words];
    let mut size = (words * 4) as u32;
    let status = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
            u32::from(AF_INET),
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if status != 0 {
        return None;
    }

    let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::ptr::addr_of!((*table).table) } as *const MIB_UDPROW_OWNER_PID;

    let mut owners = HashMap::with_capacity(count);
    for index in 0..count {
        let row = unsafe { &*rows.add(index) };
        // Bound to a specific address or to all of them: a query to this core arrives on loopback,
        // and a socket bound to 0.0.0.0 can be the one that sent it.
        let local = u32::from_be(row.dwLocalAddr);
        if local != 0x7f00_0001 && local != 0 {
            continue;
        }
        owners.insert(port_of(row.dwLocalPort), row.dwOwningPid);
    }
    Some(owners)
}

/// Every loopback TCP port and the process that owns it.
///
/// The same shape as the UDP reading over a different row: a TCP row carries the connection's state
/// and its remote end as well, so the two cannot share a walk even though they share a purpose.
fn read_tcp_owners() -> Option<HashMap<u16, u32>> {
    let mut size = 0u32;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if size == 0 {
        return None;
    }

    let words = (size as usize).div_ceil(4);
    let mut buffer = vec![0u32; words];
    let mut size = (words * 4) as u32;
    let status = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != 0 {
        return None;
    }

    let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::ptr::addr_of!((*table).table) } as *const MIB_TCPROW_OWNER_PID;

    let mut owners = HashMap::with_capacity(count);
    for index in 0..count {
        let row = unsafe { &*rows.add(index) };
        // A connected socket is bound to a real address, so unlike the UDP table there is no
        // wildcard row to admit here.
        if u32::from_be(row.dwLocalAddr) != 0x7f00_0001 {
            continue;
        }
        owners.insert(port_of(row.dwLocalPort), row.dwOwningPid);
    }
    Some(owners)
}

/// The port out of the double word Windows stores it in: the number is in network order in the low
/// half, and the high half is not part of it.
fn port_of(stored: u32) -> u16 {
    u16::from_be((stored & 0xffff) as u16)
}

/// A process's executable path, or `None` when it cannot be opened or has already ended.
fn image_of(pid: u32) -> Option<String> {
    // The limited right is enough for the image name and is the one a protected process will still
    // grant; asking for more would fail on exactly the processes most worth naming.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buffer = [0u16; 260];
    let mut length = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..length as usize]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The port is stored in network order inside a double word, and reading it as a plain number
    /// gives a port nobody is listening on — which would silently make every lookup fail.
    #[test]
    fn a_port_is_read_out_of_the_word_windows_stores_it_in() {
        // 53 in network order is 0x3500 when read as a little-endian u16.
        assert_eq!(port_of(0x0000_3500), 53);
        assert_eq!(port_of(0xdead_3500), 53, "the high half is not part of it");
        assert_eq!(port_of(0x0000_5000), 80);
    }

    /// A policy names a program either by what the user picked, which is a path, or by what a
    /// factory list says, which is a file name. Both have to come out of one lookup.
    #[test]
    fn a_program_is_known_by_its_path_and_by_its_name() {
        let program = Program::from_path(r"C:\Program Files\Discord\Discord.exe".into());
        assert_eq!(program.path, r"c:\program files\discord\discord.exe");
        assert_eq!(program.name, "discord.exe");

        // A path with the other separator still yields the name after it.
        let mixed = Program::from_path("C:/Games/Steam/steam.exe".into());
        assert_eq!(mixed.name, "steam.exe");
    }

    /// The table is read at most once in a while; a lookup that misses must not read it again on
    /// the next query, or a name nobody owns would cost two system calls per question.
    fn at(port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn taken(held: &Mutex<Option<Snapshot>>) -> Option<Instant> {
        held.lock().unwrap().as_ref().map(|s| s.at)
    }

    #[test]
    fn the_table_is_not_read_again_within_its_lifetime() {
        let askers = Askers::new();
        let now = Instant::now();
        // Whatever the machine really answers, the point is that the snapshot is taken once.
        let _ = askers.of_port(From::Udp(at(1)), now);
        let first = taken(&askers.udp);
        let _ = askers.of_port(From::Udp(at(2)), now + TABLE_TTL / 2);
        assert_eq!(taken(&askers.udp), first);
    }

    /// The two protocols keep their own readings. One shared between them would answer a TCP port
    /// out of the UDP table, which does not fail — it names whichever program holds that number
    /// over there, and a rule about a program would fire for one that asked nothing.
    #[test]
    fn each_protocol_has_its_own_reading() {
        let askers = Askers::new();
        let now = Instant::now();
        let _ = askers.of_port(From::Udp(at(1)), now);
        assert!(taken(&askers.tcp).is_none(), "the tcp table was not read");

        let _ = askers.of_port(From::Tcp(at(1)), now);
        assert!(taken(&askers.tcp).is_some(), "and now it has been");
        assert_eq!(
            taken(&askers.udp),
            taken(&askers.udp),
            "without disturbing the other"
        );
    }
}
