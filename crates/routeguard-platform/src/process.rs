use std::path::PathBuf;

use routeguard_core::error::{Result, RouteGuardError};

/// Resolve process ID to executable path.
pub struct ProcessResolver;

impl ProcessResolver {
    pub fn exe_path(pid: u32) -> Result<PathBuf> {
        #[cfg(windows)]
        {
            exe_path_windows(pid)
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            Err(RouteGuardError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
fn exe_path_windows(pid: u32) -> Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::Foundation::{CloseHandle, MAX_PATH};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return Err(RouteGuardError::Platform(format!(
                "OpenProcess failed for pid {pid}"
            )));
        }

        let mut buf = vec![0u16; MAX_PATH as usize];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        if ok == 0 {
            return Err(RouteGuardError::Platform(
                "QueryFullProcessImageNameW failed".into(),
            ));
        }
        buf.truncate(size as usize);
        Ok(PathBuf::from(OsString::from_wide(&buf)))
    }
}
