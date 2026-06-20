//! Helpers for windows-wfp `IpAddrMask` construction.

#[cfg(windows)]
use std::net::IpAddr;

#[cfg(windows)]
use routeguard_core::error::{Result, RouteGuardError};
#[cfg(windows)]
use windows_wfp::IpAddrMask;

#[cfg(windows)]
pub fn from_str(s: &str) -> Result<IpAddrMask> {
    if s.contains('/') {
        IpAddrMask::from_cidr(s).map_err(|e| RouteGuardError::Routing(format!("cidr {s}: {e}")))
    } else {
        let ip: IpAddr = s
            .parse()
            .map_err(|e| RouteGuardError::Routing(format!("ip {s}: {e}")))?;
        Ok(from_ip(ip))
    }
}

#[cfg(windows)]
pub fn from_ip(ip: IpAddr) -> IpAddrMask {
    let bits = if ip.is_ipv6() { 128 } else { 32 };
    IpAddrMask::new(ip, bits)
}
