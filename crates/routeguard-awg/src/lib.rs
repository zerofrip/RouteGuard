//! AmneziaWG backend support for RouteGuard.

pub mod conf;
pub mod params;
pub mod validate;

pub use conf::{append_awg_lines, is_awg_profile, parse_awg_from_conf};
pub use params::{AwgParams, AwgParamsSummary};
pub use validate::{validate_awg_params, validate_awg_params_strict, ValidationIssue};

use async_trait::async_trait;
use routeguard_core::tunnel::TunnelBackend;

/// Modify WireGuard handshake messages for AWG compatibility (future plugins).
pub trait HandshakeModifier: Send + Sync {
    fn modify_initiation(&self, msg: &mut [u8]) -> routeguard_core::Result<()>;
    fn modify_response(&self, msg: &mut [u8]) -> routeguard_core::Result<()>;
}

/// Extended tunnel backend with AWG plugin registration.
#[async_trait]
pub trait AwgTunnelBackend: TunnelBackend {
    fn register_handshake_modifier(&mut self, modifier: Box<dyn HandshakeModifier>);
}

/// Runtime probe placeholder — use `routeguard_platform::awg::probe_awg_library` on Windows.
pub fn probe_awg_dll() -> bool {
    false
}

/// Supported AWG parameter names for capability reporting.
pub const AWG_PARAM_NAMES: &[&str] = &["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_names_non_empty() {
        assert_eq!(AWG_PARAM_NAMES.len(), 9);
    }
}
