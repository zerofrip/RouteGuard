//! Authenticode verification hooks for bundled DLLs and executables.

use std::path::Path;

use routeguard_core::RouteGuardError;
use tracing::warn;

pub type IntegrityResult<T> = Result<T, RouteGuardError>;

/// When `ROUTE_GUARD_VERIFY_SIGNATURES=1` or release channel is beta/stable, require valid Authenticode.
pub fn should_verify() -> bool {
    std::env::var("ROUTE_GUARD_VERIFY_SIGNATURES").as_deref() == Ok("1")
        || std::env::var("ROUTE_GUARD_RELEASE_CHANNEL")
            .map(|c| matches!(c.as_str(), "beta" | "stable"))
            .unwrap_or(false)
}

/// Verify PE Authenticode signature before load.
pub fn verify_pe_signature(path: &Path) -> IntegrityResult<()> {
    if !should_verify() {
        return Ok(());
    }

    if !path.exists() {
        return Err(RouteGuardError::Platform(format!(
            "missing binary for signature check: {}",
            path.display()
        )));
    }

    #[cfg(windows)]
    {
        verify_windows(path)
    }

    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(windows)]
fn verify_windows(path: &Path) -> IntegrityResult<()> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_UI_NONE,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: 0,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: 0,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut trust_data as *mut _ as *mut c_void,
        )
    };

    if status != 0 {
        return Err(RouteGuardError::Platform(format!(
            "Authenticode verification failed for {} (status {status})",
            path.display()
        )));
    }

    Ok(())
}

pub fn verify_or_warn(path: &Path) {
    if let Err(e) = verify_pe_signature(path) {
        if should_verify() {
            panic!("signature verification failed: {e}");
        }
        warn!("{e}");
    }
}
