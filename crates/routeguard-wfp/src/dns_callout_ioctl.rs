//! Shared IOCTL definitions — must match `drivers/routeguard-callout/include/rg_callout_ioctl.h`.

use serde::Serialize;

pub const RG_CALLOUT_USER_PATH: &str = r"\\.\RouteGuardCallout";

pub const RG_DNS_CONFIG_VERSION: u32 = 1;
pub const RG_DNS_MAX_EXCLUDED_PIDS: usize = 16;

const RG_IOCTL_DEVICE_TYPE: u32 = 0x8000;
const METHOD_BUFFERED: u32 = 0;
const FILE_WRITE_DATA: u32 = 2;
const FILE_READ_DATA: u32 = 1;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_RG_DNS_SET_CONFIG: u32 = ctl_code(
    RG_IOCTL_DEVICE_TYPE,
    0x800,
    METHOD_BUFFERED,
    FILE_WRITE_DATA,
);
pub const IOCTL_RG_DNS_GET_STATUS: u32 =
    ctl_code(RG_IOCTL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_RG_DNS_GET_STATS: u32 =
    ctl_code(RG_IOCTL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA);

#[repr(C, packed(1))]
#[derive(Debug, Clone, Copy)]
pub struct RgDnsRedirectConfig {
    pub version: u32,
    pub enabled: u8,
    pub proxy_port: u16,
    pub proxy_v4: [u8; 4],
    pub proxy_v6: [u8; 16],
    pub excluded_pid_count: u32,
    pub excluded_pids: [u32; RG_DNS_MAX_EXCLUDED_PIDS],
    pub upstream_permit_count: u32,
}

#[repr(C, packed(1))]
#[derive(Debug, Clone, Copy, Default)]
pub struct RgDnsRedirectStatus {
    pub version: u32,
    pub enabled: u8,
    pub driver_ready: u8,
    pub proxy_port: u16,
    pub driver_version_major: u32,
    pub driver_version_minor: u32,
}

#[repr(C, packed(1))]
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct RgDnsRedirectStats {
    pub redirected_v4: u64,
    pub redirected_v6: u64,
    pub redirected_tcp_v4: u64,
    pub redirected_tcp_v6: u64,
    pub skipped_loopback: u64,
    pub skipped_excluded: u64,
    pub skipped_disabled: u64,
    pub errors: u64,
}

impl RgDnsRedirectConfig {
    pub fn loopback_v4(proxy_port: u16, enabled: bool, excluded_pids: &[u32]) -> Self {
        let mut cfg = Self {
            version: RG_DNS_CONFIG_VERSION,
            enabled: u8::from(enabled),
            proxy_port,
            proxy_v4: [127, 0, 0, 1],
            proxy_v6: loopback_v6(),
            excluded_pid_count: excluded_pids.len().min(RG_DNS_MAX_EXCLUDED_PIDS) as u32,
            excluded_pids: [0; RG_DNS_MAX_EXCLUDED_PIDS],
            upstream_permit_count: 0,
        };
        for (i, pid) in excluded_pids
            .iter()
            .take(RG_DNS_MAX_EXCLUDED_PIDS)
            .enumerate()
        {
            cfg.excluded_pids[i] = *pid;
        }
        cfg
    }
}

fn loopback_v6() -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[15] = 1;
    addr
}

pub fn config_size() -> usize {
    std::mem::size_of::<RgDnsRedirectConfig>()
}

pub fn status_size() -> usize {
    std::mem::size_of::<RgDnsRedirectStatus>()
}

pub fn stats_size() -> usize {
    std::mem::size_of::<RgDnsRedirectStats>()
}

/// WFP callout GUIDs — must match `rg_callout_guids.h`.
pub mod guids {
    use uuid::Uuid;

    pub fn dns_datagram_v4() -> Uuid {
        Uuid::from_u128(0xa1b2c3d4_e5f6_7890_abcd_ef1234567801)
    }

    pub fn dns_datagram_v6() -> Uuid {
        Uuid::from_u128(0xa1b2c3d4_e5f6_7890_abcd_ef1234567802)
    }

    pub fn dns_connect_redirect_v4() -> Uuid {
        Uuid::from_u128(0xa1b2c3d4_e5f6_7890_abcd_ef1234567803)
    }

    pub fn dns_connect_redirect_v6() -> Uuid {
        Uuid::from_u128(0xa1b2c3d4_e5f6_7890_abcd_ef1234567804)
    }

    pub fn provider_dns() -> Uuid {
        Uuid::from_u128(0xb2c3d4e5_f6a7_8901_bcde_f12345678901)
    }

    pub const DNS_DATAGRAM_V4: &str = "A1B2C3D4-E5F6-7890-ABCD-EF1234567801";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_struct_size_stable() {
        assert!(config_size() >= 64);
        assert!(status_size() >= 16);
        assert!(stats_size() >= 64);
    }

    #[test]
    fn loopback_config() {
        let cfg = RgDnsRedirectConfig::loopback_v4(5353, true, &[1234]);
        let version = cfg.version;
        let enabled = cfg.enabled;
        let proxy_port = cfg.proxy_port;
        let pid0 = cfg.excluded_pids[0];
        let proxy_v4 = cfg.proxy_v4;
        assert_eq!(version, RG_DNS_CONFIG_VERSION);
        assert_eq!(enabled, 1);
        assert_eq!(proxy_port, 5353);
        assert_eq!(pid0, 1234);
        assert_eq!(proxy_v4, [127, 0, 0, 1]);
    }

    #[test]
    fn ioctl_codes_match_wdk() {
        assert_eq!(IOCTL_RG_DNS_SET_CONFIG, 0x8000_A000);
        assert_eq!(IOCTL_RG_DNS_GET_STATUS, 0x8000_6004);
        assert_eq!(IOCTL_RG_DNS_GET_STATS, 0x8000_6008);
    }

    #[test]
    fn guids_match_header() {
        assert_eq!(
            guids::dns_datagram_v4().to_string().to_uppercase(),
            guids::DNS_DATAGRAM_V4
        );
    }
}
