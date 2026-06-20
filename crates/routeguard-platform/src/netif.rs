//! Physical network interface discovery.

use routeguard_core::error::{Result, RouteGuardError};

/// Discover the default physical interface index, excluding the tunnel adapter.
pub fn discover_physical_if_index(exclude_if_index: u32) -> Result<u32> {
    #[cfg(windows)]
    {
        return discover_physical_if_index_impl(exclude_if_index);
    }
    #[cfg(not(windows))]
    {
        let _ = exclude_if_index;
        Err(RouteGuardError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
fn discover_physical_if_index_impl(exclude_if_index: u32) -> Result<u32> {
    use std::net::Ipv4Addr;

    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetBestRoute2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPPROTO_NETMGMT,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

    let dest: Ipv4Addr = "8.8.8.8".parse().expect("valid ip");
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };

    let mut best: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    best.Ipv4.sin_family = AF_INET as u16;
    best.Ipv4.sin_addr.s_addr = u32::from_ne_bytes(dest.octets());

    let mut if_index = 0u32;
    let status = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &best,
            0,
            &mut row,
            &mut best,
            &mut if_index,
        )
    };

    if status != 0 {
        return Err(RouteGuardError::Platform(format!(
            "GetBestRoute2 failed: {status}"
        )));
    }

    if if_index == 0 || if_index == exclude_if_index {
        // Fallback: enumerate adapters and pick first up non-loopback != tunnel
        if_index = enumerate_fallback(exclude_if_index)?;
    }

    Ok(if_index)
}

#[cfg(windows)]
fn enumerate_fallback(exclude_if_index: u32) -> Result<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let mut buf_len = 0u32;
    unsafe {
        let _ = GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut buf_len,
        );
    }

    if buf_len == 0 {
        return Err(RouteGuardError::Platform("no adapters".into()));
    }

    let mut buffer = vec![0u8; buf_len as usize];
    let status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            std::ptr::null(),
            buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };

    if status != 0 {
        return Err(RouteGuardError::Platform(format!(
            "GetAdaptersAddresses failed: {status}"
        )));
    }

    let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let idx = adapter.IfIndex;
        if idx != 0 && idx != exclude_if_index && adapter.OperStatus == 1 {
            return Ok(idx);
        }
        current = adapter.Next;
    }

    Err(RouteGuardError::Platform(
        "no physical interface found".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_on_non_windows() {
        #[cfg(not(windows))]
        assert!(discover_physical_if_index(1).is_err());
    }
}
