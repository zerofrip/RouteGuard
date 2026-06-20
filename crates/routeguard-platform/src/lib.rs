//! Platform-specific implementations (Windows first).

pub mod awg;
pub mod dns;
pub mod integrity;
pub mod netif;
pub mod process;
pub mod routes;
pub mod transport;
pub mod tunnel;

#[cfg(windows)]
pub mod wgnt;

pub use awg::{probe_awg_library, AwgBackend};
pub use dns::{DnsInterceptor, DnsProxy, DnsProxyConfig, DnsResponseCallback};
pub use netif::discover_physical_if_index;
pub use process::ProcessResolver;
pub use routes::{RouteHandle, RouteTable, RouteTableManager, SessionRoutes};
pub use transport::DirectUdpBackend;
pub use tunnel::WireGuardNtBackend;

#[cfg(not(windows))]
pub fn platform_name() -> &'static str {
    "stub"
}

#[cfg(windows)]
pub fn platform_name() -> &'static str {
    "windows"
}
