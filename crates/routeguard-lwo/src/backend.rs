//! LWO transport backend — Mullvad-compatible in-process UDP obfuscation.

use std::net::SocketAddr;

use async_trait::async_trait;
use routeguard_core::error::{Result, RouteGuardError};
use routeguard_core::transport::{
    PolicyTransportEndpoints, TransportBackend, TransportHealth, TransportKind,
    TransportProbeResult, TransportSession, TransportValidateResult, TransportValidationIssue,
    TunnelTransportConfig, resolve_lwo_remote_udp,
};

use crate::keys::parse_lwo_keys;
use crate::relay::LwoRelay;
use crate::session;

pub struct LwoBackend;

impl LwoBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LwoBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn pick_local_listen(cfg: &TunnelTransportConfig) -> Result<SocketAddr> {
    if let Some(ref l) = cfg.lwo {
        if let Some(ref s) = l.local_listen {
            return s
                .parse()
                .map_err(|e| RouteGuardError::Config(format!("invalid local_listen: {e}")));
        }
    }
    Ok("127.0.0.1:0".parse().unwrap())
}

#[async_trait]
impl TransportBackend for LwoBackend {
    fn kind(&self) -> TransportKind {
        TransportKind::Lwo
    }

    fn name(&self) -> &str {
        "lwo"
    }

    fn probe(&self) -> TransportProbeResult {
        TransportProbeResult {
            available: true,
            binary_path: None,
            reason: None,
        }
    }

    fn validate(&self, conf_text: &str, cfg: &TunnelTransportConfig) -> TransportValidateResult {
        let mut issues = Vec::new();

        if parse_lwo_keys(conf_text).is_err() {
            issues.push(TransportValidationIssue {
                field: "lwo.keys".into(),
                message: "LWO requires valid Interface PrivateKey and Peer PublicKey".into(),
            });
        }

        let peer = routeguard_core::transport::parse_peer_endpoint(conf_text);
        let has_remote = cfg
            .lwo
            .as_ref()
            .and_then(|l| l.remote_udp.as_ref())
            .is_some()
            || peer.is_some();

        if !has_remote {
            issues.push(TransportValidationIssue {
                field: "transport.lwo.remoteUdp".into(),
                message: "LWO requires RemoteUDP or peer Endpoint".into(),
            });
        }

        if cfg.require_lwo && parse_lwo_keys(conf_text).is_err() {
            issues.push(TransportValidationIssue {
                field: "transport.requireLwo".into(),
                message: "require_lwo set but keys invalid".into(),
            });
        }

        TransportValidateResult {
            valid: issues.is_empty(),
            issues,
        }
    }

    fn recommended_mtu(&self, link_mtu: u16) -> u16 {
        link_mtu.saturating_sub(80)
    }

    fn policy_endpoints(&self, session: &TransportSession) -> PolicyTransportEndpoints {
        let remote = session.remote_transport.unwrap_or(session.original_endpoint);
        PolicyTransportEndpoints {
            wireguard_endpoint: session.wireguard_endpoint,
            original_endpoint: session.original_endpoint,
            bypass_ips: vec![remote.ip()],
            extra_permits: vec![],
        }
    }

    async fn up(
        &self,
        cfg: &TunnelTransportConfig,
        peer_endpoint: SocketAddr,
        conf_text: &str,
    ) -> Result<TransportSession> {
        let keys = parse_lwo_keys(conf_text)?;
        let remote = resolve_lwo_remote_udp(cfg, peer_endpoint)?;
        let local_listen = pick_local_listen(cfg)?;

        let relay = LwoRelay::start(&keys, remote, Some(local_listen))
            .await
            .map_err(|e| RouteGuardError::Platform(format!("LWO relay start: {e}")))?;

        let (handle_id, local) = session::insert(relay);

        Ok(TransportSession {
            kind: TransportKind::Lwo,
            handle_id,
            wireguard_endpoint: local,
            original_endpoint: peer_endpoint,
            remote_transport: Some(remote),
            effective_mtu: self.recommended_mtu(1500),
            protocol_version: cfg.lwo.as_ref().map(|l| l.protocol_version).unwrap_or(0),
            wire_format: Some("mullvad".into()),
        })
    }

    async fn down(&self, session: &TransportSession) -> Result<()> {
        session::remove(session.handle_id);
        Ok(())
    }

    async fn health(&self, session: &TransportSession) -> TransportHealth {
        if session::is_healthy(session.handle_id) {
            TransportHealth::Healthy
        } else {
            TransportHealth::Failed
        }
    }
}
