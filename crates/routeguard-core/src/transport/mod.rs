//! Transport layer — orthogonal to tunnel backend (WireGuardNT / AWG).

mod conf;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use conf::{
    conf_wants_lwo, conf_wants_phantun, merge_transport_config, parse_peer_endpoint,
    parse_routeguard_section, resolve_lwo_remote_udp, resolve_phantun_remote_tcp,
    rewrite_conf_endpoint, runtime_conf_path, transport_hints_from_conf, RouteGuardConfSection,
};

use crate::config::TunnelConfig;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    #[default]
    DirectUdp,
    Phantun,
    Lwo,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectUdp => "direct_udp",
            Self::Phantun => "phantun",
            Self::Lwo => "lwo",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportPreference {
    #[default]
    Auto,
    DirectUdp,
    Phantun,
    Lwo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PhantunTransportConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_tcp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_listen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LwoTransportConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_udp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_listen: Option<String>,
    #[serde(default)]
    pub protocol_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TunnelTransportConfig {
    #[serde(default)]
    pub preference: TransportPreference,
    #[serde(default)]
    pub require_phantun: bool,
    #[serde(default)]
    pub require_lwo: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phantun: Option<PhantunTransportConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lwo: Option<LwoTransportConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedTransport {
    pub kind: TransportKind,
    pub fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<TransportKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportCapabilities {
    pub kind: TransportKind,
    pub available: bool,
    pub default_mtu_delta: u16,
    pub supports_ipv6: bool,
    pub requires_binary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportProbeResult {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportValidateResult {
    pub valid: bool,
    pub issues: Vec<TransportValidationIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportValidationIssue {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportPermitRule {
    pub remote_ip: IpAddr,
    pub remote_port: Option<u16>,
    pub protocol: TransportProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTransportEndpoints {
    pub wireguard_endpoint: SocketAddr,
    pub original_endpoint: SocketAddr,
    pub bypass_ips: Vec<IpAddr>,
    pub extra_permits: Vec<TransportPermitRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportSession {
    pub kind: TransportKind,
    pub handle_id: u64,
    pub wireguard_endpoint: SocketAddr,
    pub original_endpoint: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_transport: Option<SocketAddr>,
    pub effective_mtu: u16,
    #[serde(default)]
    pub protocol_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_format: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportHealth {
    Healthy,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedConnect {
    pub tunnel_config: TunnelConfig,
    pub runtime_conf_path: PathBuf,
    pub transport_session: Option<TransportSession>,
    pub effective_mtu: u16,
    pub resolved: ResolvedTransport,
}

/// UDP path to peer (direct, Phantun, or LWO).
#[async_trait]
pub trait TransportBackend: Send + Sync {
    fn kind(&self) -> TransportKind;
    fn name(&self) -> &str;
    fn probe(&self) -> TransportProbeResult;
    fn validate(&self, conf_text: &str, cfg: &TunnelTransportConfig) -> TransportValidateResult;
    fn recommended_mtu(&self, link_mtu: u16) -> u16;
    fn policy_endpoints(&self, session: &TransportSession) -> PolicyTransportEndpoints;

    async fn up(
        &self,
        cfg: &TunnelTransportConfig,
        peer_endpoint: SocketAddr,
        conf_text: &str,
    ) -> Result<TransportSession>;

    async fn down(&self, session: &TransportSession) -> Result<()>;

    async fn health(&self, session: &TransportSession) -> TransportHealth;
}

pub fn transport_summary(kind: TransportKind, remote: Option<&SocketAddr>) -> String {
    match kind {
        TransportKind::DirectUdp => "direct_udp".into(),
        TransportKind::Phantun => remote
            .map(|a| format!("phantun → {a}"))
            .unwrap_or_else(|| "phantun".into()),
        TransportKind::Lwo => remote
            .map(|a| format!("lwo → {a}"))
            .unwrap_or_else(|| "lwo".into()),
    }
}
