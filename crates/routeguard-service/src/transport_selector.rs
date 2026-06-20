//! Select direct UDP vs Phantun vs LWO transport per profile and config.

use std::net::SocketAddr;

use routeguard_core::error::{Result, RouteGuardError};
use routeguard_core::transport::{
    conf_wants_lwo, conf_wants_phantun, merge_transport_config, parse_peer_endpoint,
    rewrite_conf_endpoint, runtime_conf_path, transport_hints_from_conf,
};
use routeguard_core::transport::{
    PreparedConnect, ResolvedTransport, TransportBackend, TransportCapabilities,
    TransportKind, TransportPreference, TransportSession, TunnelTransportConfig,
};
use routeguard_lwo::LwoBackend;
use routeguard_phantun::PhantunBackend;
use routeguard_platform::DirectUdpBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportChoice {
    DirectUdp,
    Phantun,
    Lwo,
}

pub struct TransportSelector {
    direct: DirectUdpBackend,
    phantun: PhantunBackend,
    lwo: LwoBackend,
}

impl TransportSelector {
    pub fn new() -> Self {
        Self {
            direct: DirectUdpBackend::new(),
            phantun: PhantunBackend::new(),
            lwo: LwoBackend::new(),
        }
    }

    pub fn probe_phantun(&self) -> bool {
        self.phantun.probe().available
    }

    pub fn probe_lwo(&self) -> bool {
        self.lwo.probe().available
    }

    pub fn capabilities(&self) -> Vec<TransportCapabilities> {
        let direct_probe = self.direct.probe();
        let phantun_probe = self.phantun.probe();
        vec![
            TransportCapabilities {
                kind: TransportKind::DirectUdp,
                available: direct_probe.available,
                default_mtu_delta: 80,
                supports_ipv6: true,
                requires_binary: false,
                binary_path: None,
                protocol_version: None,
                wire_format: None,
            },
            TransportCapabilities {
                kind: TransportKind::Phantun,
                available: phantun_probe.available,
                default_mtu_delta: 72,
                supports_ipv6: true,
                requires_binary: true,
                binary_path: phantun_probe.binary_path,
                protocol_version: None,
                wire_format: None,
            },
            TransportCapabilities {
                kind: TransportKind::Lwo,
                available: self.lwo.probe().available,
                default_mtu_delta: 80,
                supports_ipv6: true,
                requires_binary: false,
                binary_path: None,
                protocol_version: Some(0),
                wire_format: Some("mullvad".into()),
            },
        ]
    }

    pub fn resolve(
        &self,
        conf_text: &str,
        tunnel_transport: &TunnelTransportConfig,
        profile: Option<&TunnelTransportConfig>,
        override_cfg: Option<&TunnelTransportConfig>,
    ) -> Result<(ResolvedTransport, TransportChoice, TunnelTransportConfig)> {
        let hints = transport_hints_from_conf(conf_text);
        let merged = merge_transport_config(&hints, profile, override_cfg.or(Some(tunnel_transport)));

        match merged.preference {
            TransportPreference::DirectUdp => {
                return Ok((
                    ResolvedTransport {
                        kind: TransportKind::DirectUdp,
                        fallback: false,
                        fallback_reason: None,
                        requested: None,
                    },
                    TransportChoice::DirectUdp,
                    merged,
                ));
            }
            TransportPreference::Lwo => {
                return self.resolve_lwo(conf_text, merged, true);
            }
            TransportPreference::Phantun => {
                return self.resolve_phantun(conf_text, merged, true);
            }
            TransportPreference::Auto => {}
        }

        let want_lwo = merged.lwo.is_some() || conf_wants_lwo(conf_text);
        let want_phantun = merged.phantun.is_some() || conf_wants_phantun(conf_text);

        if want_lwo && want_phantun && merged.require_phantun && merged.require_lwo {
            return Err(RouteGuardError::Config(
                "conflicting require_lwo and require_phantun".into(),
            ));
        }

        if want_lwo {
            return self.resolve_lwo(conf_text, merged, false);
        }

        if want_phantun {
            return self.resolve_phantun(conf_text, merged, false);
        }

        Ok((
            ResolvedTransport {
                kind: TransportKind::DirectUdp,
                fallback: false,
                fallback_reason: None,
                requested: None,
            },
            TransportChoice::DirectUdp,
            merged,
        ))
    }

    fn resolve_lwo(
        &self,
        conf_text: &str,
        merged: TunnelTransportConfig,
        explicit: bool,
    ) -> Result<(ResolvedTransport, TransportChoice, TunnelTransportConfig)> {
        let validation = self.lwo.validate(conf_text, &merged);
        if !validation.valid {
            if merged.require_lwo || explicit {
                return Err(RouteGuardError::Config(format!(
                    "LWO validation failed: {:?}",
                    validation.issues
                )));
            }
            return Ok((
                ResolvedTransport {
                    kind: TransportKind::DirectUdp,
                    fallback: true,
                    fallback_reason: Some("lwo_validation_failed".into()),
                    requested: Some(TransportKind::Lwo),
                },
                TransportChoice::DirectUdp,
                merged,
            ));
        }

        Ok((
            ResolvedTransport {
                kind: TransportKind::Lwo,
                fallback: false,
                fallback_reason: None,
                requested: None,
            },
            TransportChoice::Lwo,
            merged,
        ))
    }

    fn resolve_phantun(
        &self,
        _conf_text: &str,
        merged: TunnelTransportConfig,
        explicit: bool,
    ) -> Result<(ResolvedTransport, TransportChoice, TunnelTransportConfig)> {
        let phantun_avail = self.phantun.probe().available;

        if phantun_avail {
            return Ok((
                ResolvedTransport {
                    kind: TransportKind::Phantun,
                    fallback: false,
                    fallback_reason: None,
                    requested: None,
                },
                TransportChoice::Phantun,
                merged,
            ));
        }

        if merged.require_phantun || explicit {
            return Err(RouteGuardError::Platform(
                "transport=phantun requires phantun_client.exe".into(),
            ));
        }

        Ok((
            ResolvedTransport {
                kind: TransportKind::DirectUdp,
                fallback: true,
                fallback_reason: Some("phantun_unavailable".into()),
                requested: Some(TransportKind::Phantun),
            },
            TransportChoice::DirectUdp,
            merged,
        ))
    }

    pub async fn prepare(
        &self,
        choice: TransportChoice,
        merged: &TunnelTransportConfig,
        peer_endpoint: SocketAddr,
        name: &str,
        conf_text: &str,
        resolved: &ResolvedTransport,
    ) -> Result<PreparedConnect> {
        let backend = self.backend(choice);
        let session = backend.up(merged, peer_endpoint, conf_text).await?;
        let effective_mtu = session.effective_mtu;
        let rewritten =
            rewrite_conf_endpoint(conf_text, session.wireguard_endpoint, Some(effective_mtu))?;
        let path = runtime_conf_path(name);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, &rewritten).await?;

        Ok(PreparedConnect {
            tunnel_config: routeguard_core::config::TunnelConfig {
                name: name.to_string(),
                config_path: path.clone(),
                mtu: effective_mtu,
                backend: Default::default(),
                require_awg: false,
                transport: merged.clone(),
            },
            runtime_conf_path: path,
            transport_session: Some(session),
            effective_mtu,
            resolved: resolved.clone(),
        })
    }

    pub async fn restart(
        &self,
        choice: TransportChoice,
        merged: &TunnelTransportConfig,
        peer_endpoint: SocketAddr,
        name: &str,
        conf_text: &str,
        resolved: &ResolvedTransport,
        old: &TransportSession,
    ) -> Result<PreparedConnect> {
        self.down(choice, old).await?;
        self.prepare(choice, merged, peer_endpoint, name, conf_text, resolved)
            .await
    }

    pub async fn down(&self, choice: TransportChoice, session: &TransportSession) -> Result<()> {
        self.backend(choice).down(session).await
    }

    pub fn policy_endpoints(
        &self,
        choice: TransportChoice,
        session: &TransportSession,
    ) -> routeguard_core::transport::PolicyTransportEndpoints {
        self.backend(choice).policy_endpoints(session)
    }

    pub fn health(&self, choice: TransportChoice, session: &TransportSession) -> routeguard_core::transport::TransportHealth {
        // sync wrapper not available - health checked via async in handler
        match choice {
            TransportChoice::DirectUdp => routeguard_core::transport::TransportHealth::Healthy,
            _ => routeguard_core::transport::TransportHealth::Healthy,
        }
    }

    pub async fn health_async(
        &self,
        choice: TransportChoice,
        session: &TransportSession,
    ) -> routeguard_core::transport::TransportHealth {
        self.backend(choice).health(session).await
    }

    fn backend(&self, choice: TransportChoice) -> &dyn TransportBackend {
        match choice {
            TransportChoice::DirectUdp => &self.direct,
            TransportChoice::Phantun => &self.phantun,
            TransportChoice::Lwo => &self.lwo,
        }
    }
}

impl Default for TransportSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_resolves_direct_udp_without_routeguard_section() {
        let conf = "[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = y\nEndpoint = 1.2.3.4:51820\n";
        let sel = TransportSelector::new();
        let (resolved, choice, _) = sel
            .resolve(conf, &TunnelTransportConfig::default(), None, None)
            .unwrap();
        assert_eq!(resolved.kind, TransportKind::DirectUdp);
        assert_eq!(choice, TransportChoice::DirectUdp);
        assert!(!resolved.fallback);
    }

    #[test]
    fn lwo_preference_with_valid_keys() {
        let conf = "[RouteGuard]\nTransport = lwo\n\n[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n[Peer]\nPublicKey = 8Ka2l4T0tVrSR5pkcsvRG++mBlxfuf8XOxpqBkOCikU=\nEndpoint = 1.2.3.4:51820\n";
        let sel = TransportSelector::new();
        let (resolved, choice, _) = sel
            .resolve(conf, &TunnelTransportConfig::default(), None, None)
            .unwrap();
        assert_eq!(resolved.kind, TransportKind::Lwo);
        assert_eq!(choice, TransportChoice::Lwo);
    }
}
