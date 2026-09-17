//! Interface-change notifications from Windows.
//!
//! The tunnel rides on whatever interface the machine is using, and that interface can go away
//! without the tunnel being told: a lid closes, a Wi-Fi association drops, a cable moves the
//! default route. The connection is left hanging — neither closed nor carrying — and only the
//! keepalive finds it, up to five seconds later.
//!
//! `NotifyIpInterfaceChange` calls back whenever an interface appears, goes away or changes, on a
//! thread of its own. The callback here records that the line moved, which costs one keepalive
//! asked now rather than at the end of its interval.
//!
//! **Not a reconnect.** An unrelated adapter appearing — a virtual switch, a phone — is no reason
//! to spend a handshake on a working tunnel. Asking early is free when the answer is yes.
//!
//! `NotifyRouteChange2` cannot be used, despite being the natural choice: this core writes hundreds of
//! routes on bring-up and more on every policy edit, and each write would come back as a
//! notification asking the tunnel to check itself. The interface notification has the same hazard
//! in smaller form, since the adapter this core owns is an interface too, hence the filter on its
//! identifier and the test that pins it.

use std::ffi::c_void;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceLuidToAlias, MIB_IPINTERFACE_ROW,
    MIB_NOTIFICATION_TYPE, MibAddInstance, MibDeleteInstance, MibInitialNotification,
    NotifyIpInterfaceChange,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use crate::core::Core;

/// What the callback is given, and what has to outlive the notification.
struct Watched {
    core: Arc<Core>,
    /// The adapter this core owns. Changes to it are this core's own doing.
    ours: u64,
}

/// A registration, cancelled when this is dropped.
///
/// Holding it is what keeps the notification alive; dropping it is what makes it stop, and in that
/// order — `CancelMibChangeNotify2` does not return until any callback in progress has finished,
/// so nothing is left running against a context that is about to go.
pub struct Watch {
    handle: HANDLE,
    /// Boxed and kept, because Windows holds a pointer to it for as long as the registration
    /// stands. Never read from here; the callback is what reads it.
    _watched: Box<Watched>,
}

// The handle is a registration with no thread affinity, and the context behind it is only ever
// read — by the callback, which Windows serialises against the cancellation.
unsafe impl Send for Watch {}
unsafe impl Sync for Watch {}

impl Drop for Watch {
    fn drop(&mut self) {
        unsafe { CancelMibChangeNotify2(self.handle) };
    }
}

/// Ask Windows to say when an interface changes, and tell the core when one that is not ours does.
///
/// Returns nothing when the registration is refused. That is not fatal and not worth failing a
/// bring-up over: without it the tunnel is exactly as it was before this existed, which is to say
/// it finds a dead link by keepalive a few seconds later.
pub fn watch(core: Arc<Core>) -> Option<Watch> {
    let watched = Box::new(Watched {
        ours: core.adapter().luid(),
        core,
    });
    let mut handle: HANDLE = std::ptr::null_mut();
    let status = unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC,
            Some(changed),
            std::ptr::from_ref(watched.as_ref()).cast::<c_void>(),
            // No initial notification: it says what the machine looks like now, and this is only
            // interested in it changing.
            false,
            &mut handle,
        )
    };
    match status {
        NO_ERROR => Some(Watch {
            handle,
            _watched: watched,
        }),
        code => {
            warn!(
                "link",
                "interface changes will not be reported (error {code})"
            );
            None
        }
    }
}

/// Called by Windows, on a thread of its own, once per change.
///
/// It does one thing and does it without waiting for anything. A callback that blocked would hold
/// a thread of the operating system's pool, and one that called back into IP Helper could deadlock
/// against the notification it is being delivered by.
unsafe extern "system" fn changed(
    context: *const c_void,
    row: *const MIB_IPINTERFACE_ROW,
    kind: MIB_NOTIFICATION_TYPE,
) {
    let Some(watched) = (unsafe { context.cast::<Watched>().as_ref() }) else {
        return;
    };
    // The identifier is a union of the same eight bytes read two ways; this reads the whole,
    // which is the way Windows compares one interface with another.
    let of = unsafe { row.as_ref() }.map(|row| unsafe { row.InterfaceLuid.Value });
    if worth_reacting(kind, of, watched.ours) {
        watched.core.line_changed(of.unwrap_or(0), kind);
    }
}

/// A line change in words: the interface by the name Windows shows for it, and what happened to it.
///
/// An interface that has already gone has no name left to look up, and is named by its LUID.
pub fn describe(interface: u64, kind: MIB_NOTIFICATION_TYPE) -> String {
    let what = if kind == MibAddInstance {
        "appeared"
    } else if kind == MibDeleteInstance {
        "went away"
    } else {
        "changed"
    };
    if interface == 0 {
        return format!("an interface {what}");
    }
    match alias(interface) {
        Some(name) => format!("interface {name} {what}"),
        None => format!("interface {interface:#x} {what}"),
    }
}

/// The name Windows shows for an interface — `Wi-Fi`, `Ethernet 2` — or `None` when it has none.
fn alias(interface: u64) -> Option<String> {
    // NDIS_IF_MAX_STRING_SIZE, plus the terminator.
    let mut buffer = [0u16; 257];
    let luid = NET_LUID_LH { Value: interface };
    let status = unsafe { ConvertInterfaceLuidToAlias(&luid, buffer.as_mut_ptr(), buffer.len()) };
    if status != NO_ERROR {
        return None;
    }
    let length = buffer
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..length]))
}

/// Whether a notification says something about the line rather than about this core.
///
/// The adapter this core owns is an interface like any other, and this core changes it constantly:
/// every route it installs is a change to it. Reacting to those would have the tunnel ask the
/// endpoint whether it is still there once per route — hundreds of times on bring-up.
fn worth_reacting(kind: MIB_NOTIFICATION_TYPE, of: Option<u64>, ours: u64) -> bool {
    // The initial notification describes the machine as it already is, and carries no row.
    if kind == MibInitialNotification {
        return false;
    }
    match of {
        Some(luid) => luid != ours,
        // A change that names no interface cannot be attributed, and the cost of being wrong here
        // is one keepalive asked early.
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MibAddInstance, MibDeleteInstance, MibParameterNotification,
    };

    const OURS: u64 = 0x1234_5678_9abc_def0;

    /// The filter this module exists for. Without it every route this core installs comes back as
    /// a change to react to, and a bring-up that installs five hundred of them would ask the
    /// endpoint whether it is still there five hundred times.
    #[test]
    fn changes_to_our_own_adapter_are_not_changes_to_the_line() {
        assert!(!worth_reacting(MibParameterNotification, Some(OURS), OURS));
        assert!(!worth_reacting(MibAddInstance, Some(OURS), OURS));
        assert!(!worth_reacting(MibDeleteInstance, Some(OURS), OURS));
    }

    /// And every other interface is the line, whichever way it moved.
    #[test]
    fn a_change_to_any_other_interface_is_worth_asking_about() {
        assert!(worth_reacting(MibAddInstance, Some(9), OURS));
        assert!(worth_reacting(MibDeleteInstance, Some(9), OURS));
        assert!(worth_reacting(MibParameterNotification, Some(9), OURS));
    }

    /// The first notification describes what is already true, which is not news.
    #[test]
    fn the_notification_that_describes_the_present_is_not_a_change() {
        assert!(!worth_reacting(MibInitialNotification, None, OURS));
        assert!(!worth_reacting(MibInitialNotification, Some(9), OURS));
    }

    /// The registration itself, against Windows rather than against a description of it. A wrong
    /// signature here compiles and then simply never calls back, which is indistinguishable from a
    /// machine whose network never changed — so the initial notification is asked for once, purely
    /// to watch it arrive.
    #[test]
    fn windows_calls_back_through_this_registration() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        static SEEN: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "system" fn counted(
            context: *const c_void,
            _row: *const MIB_IPINTERFACE_ROW,
            _kind: MIB_NOTIFICATION_TYPE,
        ) {
            if let Some(seen) = unsafe { context.cast::<AtomicUsize>().as_ref() } {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut handle: HANDLE = std::ptr::null_mut();
        let status = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(counted),
                std::ptr::from_ref(&SEEN).cast::<c_void>(),
                true,
                &mut handle,
            )
        };
        assert_eq!(status, NO_ERROR, "the registration was refused");

        // Delivered on a thread of Windows' own, so it is waited for rather than assumed to have
        // already happened.
        for _ in 0..50 {
            if SEEN.load(Ordering::SeqCst) > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        unsafe { CancelMibChangeNotify2(handle) };
        assert!(SEEN.load(Ordering::SeqCst) > 0, "Windows never called back");
    }

    /// Unattributable, so treated as the line: the cost of being wrong is one early keepalive, and
    /// the cost of the other mistake is the failure this module exists to find.
    #[test]
    fn a_change_naming_no_interface_is_treated_as_the_line() {
        assert!(worth_reacting(MibParameterNotification, None, OURS));
    }

    /// The journal line says what happened in words, and an interface with no name left — one that
    /// has already gone — is still identifiable by its LUID rather than dropped from the sentence.
    #[test]
    fn a_line_change_is_said_in_words() {
        assert_eq!(describe(0, MibAddInstance), "an interface appeared");
        assert_eq!(describe(0, MibDeleteInstance), "an interface went away");
        assert_eq!(
            describe(0, MibParameterNotification),
            "an interface changed"
        );
        assert_eq!(
            describe(OURS, MibDeleteInstance),
            "interface 0x123456789abcdef0 went away"
        );
    }
}
