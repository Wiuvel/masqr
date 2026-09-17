//! The Windows calls this core makes, declared by hand.
//!
//! `wintun.dll` is loaded at run time rather than linked: it is a file the application ships beside
//! the binary, there is no import library, and a missing DLL has to be a message rather than a
//! process that will not start.
//!
//! The IP Helper calls are linked normally through `windows-sys`. They give the adapter its
//! address, MTU and routes; the alternative is spawning `netsh`, which costs about a second per
//! call and reports failure as text.

use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{FreeLibrary, HANDLE, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW,
};

/// A NUL-terminated UTF-16 string, which is what every `W` entry point wants.
pub fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

/// An adapter, as Wintun hands it out. Opaque, and owned by whoever created it.
pub type AdapterHandle = *mut c_void;
/// A session on an adapter: the shared ring packets are read from and written to.
pub type SessionHandle = *mut c_void;

/// The entry points of `wintun.dll`, resolved once when the library is loaded.
///
/// Every one of them is a raw pointer bound to `library`, so the struct owns the module: dropping
/// it frees the DLL, and no function pointer may outlive it.
pub struct Wintun {
    library: HMODULE,
    pub create_adapter:
        unsafe extern "system" fn(*const u16, *const u16, *const [u8; 16]) -> AdapterHandle,
    pub close_adapter: unsafe extern "system" fn(AdapterHandle),
    pub get_adapter_luid: unsafe extern "system" fn(AdapterHandle, *mut u64),
    pub get_running_driver_version: unsafe extern "system" fn() -> u32,
    pub start_session: unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle,
    pub end_session: unsafe extern "system" fn(SessionHandle),
    pub get_read_wait_event: unsafe extern "system" fn(SessionHandle) -> HANDLE,
    pub receive_packet: unsafe extern "system" fn(SessionHandle, *mut u32) -> *mut u8,
    pub release_receive_packet: unsafe extern "system" fn(SessionHandle, *const u8),
    pub allocate_send_packet: unsafe extern "system" fn(SessionHandle, u32) -> *mut u8,
    pub send_packet: unsafe extern "system" fn(SessionHandle, *const u8),
}

// The handle is a module handle and the rest are its exported functions; none of them carry thread
// affinity. What is not safe to share is a *session*, and that is guarded where sessions are used.
unsafe impl Send for Wintun {}
unsafe impl Sync for Wintun {}

#[derive(Debug, thiserror::Error)]
/// Why `wintun.dll` could not be used — missing, or not the library this expects.
pub enum LoadError {
    #[error("wintun.dll could not be loaded from {0}: {1}")]
    Library(String, std::io::Error),
    #[error("wintun.dll is missing the entry point `{0}` — it is not the library this expects")]
    Symbol(&'static str),
}

impl Wintun {
    /// Load the library from an explicit path.
    ///
    /// `LOAD_WITH_ALTERED_SEARCH_PATH` makes the DLL's own directory the first place its
    /// dependencies are looked for, so a copy sitting beside the binary resolves against itself
    /// rather than against whatever happens to be on the search path.
    // Each transmute below takes its target type from the struct field it initialises, and the
    // compiler checks that; naming the signature a second time at the call would only give it a
    // second place to be wrong.
    #[allow(clippy::missing_transmute_annotations)]
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let wide_path = wide(&path.display().to_string());
        let library = unsafe {
            LoadLibraryExW(
                wide_path.as_ptr(),
                std::ptr::null_mut(),
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        };
        if library.is_null() {
            return Err(LoadError::Library(
                path.display().to_string(),
                std::io::Error::last_os_error(),
            ));
        }

        // Every symbol or none: a partially resolved table would fail later, at a call site with
        // nothing to say about why.
        macro_rules! symbol {
            ($name:literal) => {{
                let raw = unsafe { GetProcAddress(library, concat!($name, "\0").as_ptr()) };
                match raw {
                    Some(address) => unsafe { std::mem::transmute(address) },
                    None => {
                        unsafe { FreeLibrary(library) };
                        return Err(LoadError::Symbol($name));
                    }
                }
            }};
        }

        Ok(Self {
            library,
            create_adapter: symbol!("WintunCreateAdapter"),
            close_adapter: symbol!("WintunCloseAdapter"),
            get_adapter_luid: symbol!("WintunGetAdapterLUID"),
            get_running_driver_version: symbol!("WintunGetRunningDriverVersion"),
            start_session: symbol!("WintunStartSession"),
            end_session: symbol!("WintunEndSession"),
            get_read_wait_event: symbol!("WintunGetReadWaitEvent"),
            receive_packet: symbol!("WintunReceivePacket"),
            release_receive_packet: symbol!("WintunReleaseReceivePacket"),
            allocate_send_packet: symbol!("WintunAllocateSendPacket"),
            send_packet: symbol!("WintunSendPacket"),
        })
    }
}

impl Drop for Wintun {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.library) };
    }
}
