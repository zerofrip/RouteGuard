//! Raw FFI types mirroring `wireguard.h` (WireGuardNT embeddable DLL API).

#![allow(non_camel_case_types, non_snake_case, dead_code, unexpected_cfgs)]

use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

pub type WIREGUARD_ADAPTER_HANDLE = *mut c_void;

pub const WIREGUARD_KEY_LENGTH: usize = 32;

pub type WIREGUARD_LOGGER_CALLBACK = Option<
    unsafe extern "system" fn(level: WIREGUARD_LOGGER_LEVEL, timestamp: u64, message: *const u16),
>;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WIREGUARD_LOGGER_LEVEL {
    WIREGUARD_LOG_INFO = 0,
    WIREGUARD_LOG_WARN = 1,
    WIREGUARD_LOG_ERR = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WIREGUARD_ADAPTER_LOG_STATE {
    WIREGUARD_ADAPTER_LOG_OFF = 0,
    WIREGUARD_ADAPTER_LOG_ON = 1,
    WIREGUARD_ADAPTER_LOG_ON_WITH_PREFIX = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WIREGUARD_ADAPTER_STATE {
    WIREGUARD_ADAPTER_STATE_DOWN = 0,
    WIREGUARD_ADAPTER_STATE_UP = 1,
}

pub type WIREGUARD_ALLOWED_IP_FLAG = u32;
pub const WIREGUARD_ALLOWED_IP_REMOVE: WIREGUARD_ALLOWED_IP_FLAG = 1 << 0;

pub type WIREGUARD_PEER_FLAG = u32;
pub const WIREGUARD_PEER_HAS_PUBLIC_KEY: WIREGUARD_PEER_FLAG = 1 << 0;
pub const WIREGUARD_PEER_HAS_PRESHARED_KEY: WIREGUARD_PEER_FLAG = 1 << 1;
pub const WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE: WIREGUARD_PEER_FLAG = 1 << 2;
pub const WIREGUARD_PEER_HAS_ENDPOINT: WIREGUARD_PEER_FLAG = 1 << 3;
pub const WIREGUARD_PEER_REPLACE_ALLOWED_IPS: WIREGUARD_PEER_FLAG = 1 << 5;
pub const WIREGUARD_PEER_REMOVE: WIREGUARD_PEER_FLAG = 1 << 6;
pub const WIREGUARD_PEER_UPDATE_ONLY: WIREGUARD_PEER_FLAG = 1 << 7;

pub type WIREGUARD_INTERFACE_FLAG = u32;
pub const WIREGUARD_INTERFACE_HAS_PUBLIC_KEY: WIREGUARD_INTERFACE_FLAG = 1 << 0;
pub const WIREGUARD_INTERFACE_HAS_PRIVATE_KEY: WIREGUARD_INTERFACE_FLAG = 1 << 1;
pub const WIREGUARD_INTERFACE_HAS_LISTEN_PORT: WIREGUARD_INTERFACE_FLAG = 1 << 2;
pub const WIREGUARD_INTERFACE_REPLACE_PEERS: WIREGUARD_INTERFACE_FLAG = 1 << 3;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 23;

#[repr(C)]
#[derive(Clone, Copy)]
pub union IN_ADDR {
    pub s_addr: u32,
    pub S_un: IN_ADDR_S_un,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN_ADDR_S_un {
    pub S_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN6_ADDR {
    pub u: IN6_ADDR_U,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union IN6_ADDR_U {
    pub Byte: [u8; 16],
    pub Word: [u16; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SOCKADDR_INET {
    pub Ipv4: SOCKADDR_IN,
    pub Ipv6: SOCKADDR_IN6,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR_IN {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: IN_ADDR,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SOCKADDR_IN6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: IN6_ADDR,
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union WIREGUARD_ALLOWED_IP_ADDRESS {
    pub V4: IN_ADDR,
    pub V6: IN6_ADDR,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WIREGUARD_ALLOWED_IP {
    pub Address: WIREGUARD_ALLOWED_IP_ADDRESS,
    pub AddressFamily: u16,
    pub Cidr: u8,
    pub _padding: u8,
    pub Flags: WIREGUARD_ALLOWED_IP_FLAG,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WIREGUARD_PEER {
    pub Flags: WIREGUARD_PEER_FLAG,
    pub Reserved: u32,
    pub PublicKey: [u8; WIREGUARD_KEY_LENGTH],
    pub PresharedKey: [u8; WIREGUARD_KEY_LENGTH],
    pub PersistentKeepalive: u16,
    pub _padding: u16,
    pub Endpoint: SOCKADDR_INET,
    pub TxBytes: u64,
    pub RxBytes: u64,
    pub LastHandshake: u64,
    pub AllowedIPsCount: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WIREGUARD_INTERFACE {
    pub Flags: WIREGUARD_INTERFACE_FLAG,
    pub ListenPort: u16,
    pub _padding: u16,
    pub PrivateKey: [u8; WIREGUARD_KEY_LENGTH],
    pub PublicKey: [u8; WIREGUARD_KEY_LENGTH],
    pub PeersCount: u32,
}

pub fn sockaddr_to_rust(addr: &SOCKADDR_INET, family: u16) -> Option<SocketAddr> {
    unsafe {
        if family == AF_INET {
            let sa = addr.Ipv4;
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            Some(SocketAddr::from((ip, port)))
        } else if family == AF_INET6 {
            let sa = addr.Ipv6;
            let ip = Ipv6Addr::from(sa.sin6_addr.u.Byte);
            let port = u16::from_be(sa.sin6_port);
            Some(SocketAddr::from((ip, port)))
        } else {
            None
        }
    }
}

pub fn socketaddr_to_sockaddr_inet(addr: SocketAddr) -> (SOCKADDR_INET, u16) {
    match addr {
        SocketAddr::V4(v4) => {
            let sa = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: v4.port().to_be(),
                sin_addr: IN_ADDR {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            let out = SOCKADDR_INET { Ipv4: sa };
            (out, AF_INET)
        }
        SocketAddr::V6(v6) => {
            let sa = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_U {
                        Byte: v6.ip().octets(),
                    },
                },
                sin6_scope_id: v6.scope_id(),
            };
            let out = SOCKADDR_INET { Ipv6: sa };
            (out, AF_INET6)
        }
    }
}

pub fn wireguard_epoch_to_system_time(epoch100ns: u64) -> Option<std::time::SystemTime> {
    if epoch100ns == 0 {
        return None;
    }
    const WINDOWS_EPOCH_DIFF: u64 = 11_644_473_600_000_000_000;
    let unix_ns = epoch100ns.saturating_sub(WINDOWS_EPOCH_DIFF) * 100;
    Some(std::time::UNIX_EPOCH + std::time::Duration::from_nanos(unix_ns))
}

#[cfg(wgnt_bindgen)]
include!(concat!(env!("OUT_DIR"), "/wireguard_bindings.rs"));
