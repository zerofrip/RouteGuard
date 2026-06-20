//! Direct UDP — WireGuard speaks UDP to peer endpoint unchanged.

use std::net::SocketAddr;

use async_trait::async_trait;
use routeguard_core::error::Result;
use routeguard_core::transport::{
    PolicyTransportEndpoints, TransportBackend, TransportHealth, TransportKind,
    TransportProbeResult, TransportSession, TransportValidateResult, TunnelTransportConfig,
};

pub struct DirectUdpBackend;

impl DirectUdpBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DirectUdpBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportBackend for DirectUdpBackend {
    fn kind(&self) -> TransportKind {
        TransportKind::DirectUdp
    }

    fn name(&self) -> &str {
        "direct_udp"
    }

    fn probe(&self) -> TransportProbeResult {
        TransportProbeResult {
            available: true,
            binary_path: None,
            reason: None,
        }
    }

    fn validate(&self, conf_text: &str, _cfg: &TunnelTransportConfig) -> TransportValidateResult {
        let valid = routeguard_core::transport::parse_peer_endpoint(conf_text).is_some();
        TransportValidateResult {
            valid,
            issues: if valid {
                vec![]
            } else {
                vec![routeguard_core::transport::TransportValidationIssue {
                    field: "Peer.Endpoint".into(),
                    message: "missing peer Endpoint for direct UDP".into(),
                }]
            },
        }
    }

    fn recommended_mtu(&self, link_mtu: u16) -> u16 {
        link_mtu.saturating_sub(80)
    }

    fn policy_endpoints(&self, session: &TransportSession) -> PolicyTransportEndpoints {
        PolicyTransportEndpoints {
            wireguard_endpoint: session.wireguard_endpoint,
            original_endpoint: session.original_endpoint,
            bypass_ips: vec![session.original_endpoint.ip()],
            extra_permits: vec![],
        }
    }

    async fn up(
        &self,
        _cfg: &TunnelTransportConfig,
        peer_endpoint: SocketAddr,
        _conf_text: &str,
    ) -> Result<TransportSession> {
        Ok(TransportSession {
            kind: TransportKind::DirectUdp,
            handle_id: 0,
            wireguard_endpoint: peer_endpoint,
            original_endpoint: peer_endpoint,
            remote_transport: None,
            effective_mtu: self.recommended_mtu(1500),
            protocol_version: 0,
            wire_format: None,
        })
    }

    async fn down(&self, _session: &TransportSession) -> Result<()> {
        Ok(())
    }

    async fn health(&self, _session: &TransportSession) -> TransportHealth {
        TransportHealth::Healthy
    }
}
