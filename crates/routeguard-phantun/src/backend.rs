//! Phantun UDP-over-TCP transport backend.

use std::net::SocketAddr;

use async_trait::async_trait;
use routeguard_core::error::{Result, RouteGuardError};
use routeguard_core::transport::{
    PolicyTransportEndpoints, TransportBackend, TransportHealth, TransportKind,
    TransportPermitRule, TransportProbeResult, TransportProtocol, TransportSession,
    TransportValidateResult, TransportValidationIssue, TunnelTransportConfig,
    resolve_phantun_remote_tcp,
};

use crate::supervisor::{
    is_running, pick_local_listen, probe_phantun_binary, resolve_phantun_binary, spawn_phantun,
    stop_phantun,
};

pub struct PhantunBackend;

impl PhantunBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PhantunBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportBackend for PhantunBackend {
    fn kind(&self) -> TransportKind {
        TransportKind::Phantun
    }

    fn name(&self) -> &str {
        "phantun"
    }

    fn probe(&self) -> TransportProbeResult {
        let path = resolve_phantun_binary();
        let available = probe_phantun_binary();
        TransportProbeResult {
            available,
            binary_path: Some(path.display().to_string()),
            reason: if available {
                None
            } else {
                Some("phantun_client.exe not found".into())
            },
        }
    }

    fn validate(&self, conf_text: &str, cfg: &TunnelTransportConfig) -> TransportValidateResult {
        let mut issues = Vec::new();
        let peer = routeguard_core::transport::parse_peer_endpoint(conf_text);
        let has_remote = cfg
            .phantun
            .as_ref()
            .and_then(|p| p.remote_tcp.as_ref())
            .is_some()
            || peer.is_some();

        if !has_remote {
            issues.push(TransportValidationIssue {
                field: "transport.phantun.remoteTcp".into(),
                message: "Phantun requires RemoteTCP or peer Endpoint".into(),
            });
        }

        if cfg.require_phantun && !self.probe().available {
            issues.push(TransportValidationIssue {
                field: "transport.requirePhantun".into(),
                message: "require_phantun set but phantun_client.exe missing".into(),
            });
        }

        TransportValidateResult {
            valid: issues.is_empty(),
            issues,
        }
    }

    fn recommended_mtu(&self, link_mtu: u16) -> u16 {
        link_mtu.saturating_sub(20 + 20 + 32)
    }

    fn policy_endpoints(&self, session: &TransportSession) -> PolicyTransportEndpoints {
        let remote = session.remote_transport.unwrap_or(session.original_endpoint);
        PolicyTransportEndpoints {
            wireguard_endpoint: session.wireguard_endpoint,
            original_endpoint: session.original_endpoint,
            bypass_ips: vec![remote.ip()],
            extra_permits: vec![TransportPermitRule {
                remote_ip: remote.ip(),
                remote_port: Some(remote.port()),
                protocol: TransportProtocol::Tcp,
            }],
        }
    }

    async fn up(
        &self,
        cfg: &TunnelTransportConfig,
        peer_endpoint: SocketAddr,
        _conf_text: &str,
    ) -> Result<TransportSession> {
        if !probe_phantun_binary() {
            return Err(RouteGuardError::Platform(
                "phantun_client.exe not available".into(),
            ));
        }

        let remote = resolve_phantun_remote_tcp(cfg, peer_endpoint)?;
        let local = pick_local_listen(
            cfg.phantun
                .as_ref()
                .and_then(|p| p.local_listen.as_deref()),
        )?;

        let (handle_id, bound_local) = spawn_phantun(local, remote)?;

        Ok(TransportSession {
            kind: TransportKind::Phantun,
            handle_id,
            wireguard_endpoint: bound_local,
            original_endpoint: peer_endpoint,
            remote_transport: Some(remote),
            effective_mtu: self.recommended_mtu(1500),
            protocol_version: 0,
            wire_format: None,
        })
    }

    async fn down(&self, session: &TransportSession) -> Result<()> {
        stop_phantun(session.handle_id)
    }

    async fn health(&self, session: &TransportSession) -> TransportHealth {
        if is_running(session.handle_id) {
            TransportHealth::Healthy
        } else {
            TransportHealth::Failed
        }
    }
}
