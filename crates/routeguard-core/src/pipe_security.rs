//! Named pipe security descriptors (SDDL) for production ACL hardening.

/// SDDL: SY and BA full access; AU read/write (same-machine authenticated users).
pub const DEFAULT_PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

/// Admin + System only — use when `ROUTE_GUARD_STRICT_PIPE=1`.
pub const STRICT_PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

pub fn pipe_sddl() -> &'static str {
    if std::env::var("ROUTE_GUARD_STRICT_PIPE").as_deref() == Ok("1") {
        STRICT_PIPE_SDDL
    } else {
        DEFAULT_PIPE_SDDL
    }
}

#[cfg(windows)]
pub mod win {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::RawHandle;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ConnectNamedPipe, GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    use super::pipe_sddl;

    pub fn create_secure_pipe(name: &str) -> io::Result<RawHandle> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let sddl: Vec<u16> = pipe_sddl()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut sd = ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: sd as *mut c_void,
            bInheritHandle: 0,
        };

        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                &mut sa,
            )
        };

        unsafe {
            LocalFree(sd as _);
        }

        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32
            ));
        }

        Ok(handle as RawHandle)
    }

    pub fn connect_pipe(handle: RawHandle) -> io::Result<()> {
        let ok = unsafe { ConnectNamedPipe(handle as HANDLE, ptr::null_mut()) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err != 535 {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }
        Ok(())
    }

    pub fn close_pipe(handle: RawHandle) {
        unsafe {
            CloseHandle(handle as HANDLE);
        }
    }
}
