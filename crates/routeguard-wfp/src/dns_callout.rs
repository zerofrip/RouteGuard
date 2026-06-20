//! DNS redirect via routeguard-callout.sys + WFP filters.

use routeguard_core::error::{Result, RouteGuardError};

use crate::dns_callout_ioctl::{RgDnsRedirectConfig, RgDnsRedirectStats, RgDnsRedirectStatus};

#[cfg(windows)]
use crate::dns_callout_ioctl::{
    config_size, stats_size, status_size, IOCTL_RG_DNS_GET_STATS, IOCTL_RG_DNS_GET_STATUS,
    IOCTL_RG_DNS_SET_CONFIG, RG_CALLOUT_USER_PATH,
};

#[cfg(windows)]
mod driver_io {
    use std::ffi::c_void;
    use std::ptr;

    use routeguard_core::error::{Result, RouteGuardError};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    use super::*;

    fn open_device() -> Result<HANDLE> {
        let path: Vec<u16> = RG_CALLOUT_USER_PATH
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(RouteGuardError::Platform(
                "RouteGuardCallout device not available".into(),
            ));
        }
        Ok(handle)
    }

    pub fn probe_driver() -> bool {
        match open_device() {
            Ok(h) => {
                unsafe { CloseHandle(h) };
                true
            }
            Err(_) => false,
        }
    }

    pub fn set_config(config: &RgDnsRedirectConfig) -> Result<()> {
        let handle = open_device()?;
        let mut bytes = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_RG_DNS_SET_CONFIG,
                config as *const _ as *mut c_void,
                config_size() as u32,
                ptr::null_mut(),
                0,
                &mut bytes,
                ptr::null_mut(),
            )
        };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(RouteGuardError::Platform(
                "IOCTL_RG_DNS_SET_CONFIG failed".into(),
            ));
        }
        Ok(())
    }

    pub fn get_status() -> Result<RgDnsRedirectStatus> {
        let handle = open_device()?;
        let mut status = RgDnsRedirectStatus::default();
        let mut bytes = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_RG_DNS_GET_STATUS,
                ptr::null_mut(),
                0,
                &mut status as *mut _ as *mut c_void,
                status_size() as u32,
                &mut bytes,
                ptr::null_mut(),
            )
        };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(RouteGuardError::Platform(
                "IOCTL_RG_DNS_GET_STATUS failed".into(),
            ));
        }
        Ok(status)
    }

    pub fn get_stats() -> Result<RgDnsRedirectStats> {
        let handle = open_device()?;
        let mut stats = RgDnsRedirectStats::default();
        let mut bytes = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_RG_DNS_GET_STATS,
                ptr::null_mut(),
                0,
                &mut stats as *mut _ as *mut c_void,
                stats_size() as u32,
                &mut bytes,
                ptr::null_mut(),
            )
        };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(RouteGuardError::Platform(
                "IOCTL_RG_DNS_GET_STATS failed".into(),
            ));
        }
        Ok(stats)
    }
}

#[cfg(not(windows))]
mod driver_io {
    use routeguard_core::error::{Result, RouteGuardError};

    use super::*;

    pub fn probe_driver() -> bool {
        false
    }

    #[allow(dead_code)]
    pub fn set_config(_config: &RgDnsRedirectConfig) -> Result<()> {
        Err(RouteGuardError::UnsupportedPlatform)
    }

    #[allow(dead_code)]
    pub fn get_status() -> Result<RgDnsRedirectStatus> {
        Err(RouteGuardError::UnsupportedPlatform)
    }

    pub fn get_stats() -> Result<RgDnsRedirectStats> {
        Err(RouteGuardError::UnsupportedPlatform)
    }
}

/// Manages kernel DNS redirect + user-mode WFP filters.
#[derive(Debug, Default)]
pub struct DnsCalloutManager {
    filter_ids: Vec<u64>,
    kernel_active: bool,
    driver_present: bool,
}

impl DnsCalloutManager {
    pub fn new() -> Self {
        Self {
            driver_present: driver_io::probe_driver(),
            ..Default::default()
        }
    }

    pub fn probe_driver(&mut self) -> bool {
        self.driver_present = driver_io::probe_driver();
        self.driver_present
    }

    pub fn driver_present(&self) -> bool {
        self.driver_present
    }

    pub fn kernel_active(&self) -> bool {
        self.kernel_active
    }

    pub fn filter_ids(&self) -> &[u64] {
        &self.filter_ids
    }

    pub fn get_stats(&self) -> Result<RgDnsRedirectStats> {
        driver_io::get_stats()
    }

    /// Enable kernel redirect + WFP filters.
    #[cfg(windows)]
    pub fn install(
        &mut self,
        session: &mut crate::engine::WfpSessionInner,
        proxy_port: u16,
        excluded_pids: &[u32],
        require_kernel: bool,
    ) -> Result<bool> {
        use crate::dns_callout_wfp::{install_dns_redirect_filters, remove_dns_redirect_filters};

        self.probe_driver();

        if require_kernel && !self.driver_present {
            return Err(RouteGuardError::Platform(
                "kernel_redirect requires routeguard-callout.sys".into(),
            ));
        }

        if self.driver_present {
            let cfg = RgDnsRedirectConfig::loopback_v4(proxy_port, true, excluded_pids);
            if let Err(e) = driver_io::set_config(&cfg) {
                tracing::warn!("DNS callout IOCTL set_config failed: {e}");
                if require_kernel {
                    return Err(e);
                }
            } else {
                self.kernel_active = true;
            }
        }

        remove_dns_redirect_filters(session, &self.filter_ids)?;
        self.filter_ids = install_dns_redirect_filters(session, proxy_port)?;

        Ok(self.kernel_active || !self.filter_ids.is_empty())
    }

    #[cfg(not(windows))]
    pub fn install(
        &mut self,
        _session: &mut (),
        _proxy_port: u16,
        _excluded_pids: &[u32],
        _require_kernel: bool,
    ) -> Result<bool> {
        Err(RouteGuardError::UnsupportedPlatform)
    }

    #[cfg(windows)]
    pub fn remove(&mut self, session: &mut crate::engine::WfpSessionInner) -> Result<()> {
        use crate::dns_callout_wfp::remove_dns_redirect_filters;

        if self.driver_present {
            let cfg = RgDnsRedirectConfig::loopback_v4(5353, false, &[]);
            let _ = driver_io::set_config(&cfg);
        }
        remove_dns_redirect_filters(session, &self.filter_ids)?;
        self.filter_ids.clear();
        self.kernel_active = false;
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn remove(&mut self, _session: &mut ()) -> Result<()> {
        self.filter_ids.clear();
        self.kernel_active = false;
        Ok(())
    }
}

pub fn probe_callout_driver() -> bool {
    driver_io::probe_driver()
}
