//! Native WireGuardNT backend — direct wireguard.dll FFI.

#[cfg(windows)]
pub mod adapter;
#[cfg(windows)]
pub mod bindings;
#[cfg(windows)]
pub mod config;
pub mod error;
#[cfg(windows)]
pub mod ffi;
#[cfg(windows)]
pub mod state;
#[cfg(windows)]
pub mod statistics;

pub use error::{WgntError, WgntResult};

#[cfg(windows)]
pub use adapter::{AdapterHandle, DEFAULT_POOL};
#[cfg(windows)]
pub use bindings::WIREGUARD_ADAPTER_STATE;
#[cfg(windows)]
pub use config::{parse_conf_file, parse_conf_text, serialize_interface, ParsedConf};
#[cfg(windows)]
pub use ffi::WgntLibrary;
#[cfg(windows)]
pub use statistics::{query_stats, wait_for_handshake, InterfaceStats, PeerStats};
