//! Build ObservabilitySnapshot from live service state.

use routeguard_core::backend::BackendKind;
use routeguard_core::config::RoutingMode;
use routeguard_core::observability::{
    compute_health, obs_now_iso, CapabilitiesObs, DnsDriverObs, DnsObs, DomainRoutesObs,
    NetworkLockObs, ObservabilitySnapshot, RoutingObs, RuleCountObs, ServiceObs, TransportObs,
    TransportRecoveryObs, TunnelBackendObs, TunnelObs, TunnelStatsObs,
    OBSERVABILITY_SCHEMA_VERSION,
};
use routeguard_core::policy::SessionState;
use routeguard_core::transport::{transport_summary, TransportHealth, TransportKind};
use routeguard_core::tunnel::TunnelStats;
use serde_json::json;

use crate::handler::ServiceContext;
use crate::transport_selector::TransportChoice;

pub async fn collect_snapshot(
    ctx: &ServiceContext,
    sections: Option<&[String]>,
) -> ObservabilitySnapshot {
    let all = sections.is_none();
    let want =
        |s: &str| all || sections.is_some_and(|v| v.iter().any(|x| x.eq_ignore_ascii_case(s)));

    let session_state = ctx.orchestrator.session_state().await;
    let session_str = session_state_str(&session_state);

    let handle = ctx.orchestrator.active_handle().await;
    let stats = handle
        .as_ref()
        .and_then(|h| {
            let choice = ctx.selector.choice_for(h.backend);
            ctx.selector.stats(choice, h).ok()
        })
        .unwrap_or_default();

    let cfg = ctx.orchestrator.get_config().await;
    let active_transport = ctx.active_session.active();
    let obs = &ctx.observability;

    let rx_rate = *obs.last_rx_rate.lock().unwrap();
    let tx_rate = *obs.last_tx_rate.lock().unwrap();

    let tunnel = if want("tunnel") {
        handle.as_ref().map(|h| {
            let choice = ctx.selector.choice_for(h.backend);
            let lifecycle = format!("{:?}", ctx.selector.status(choice, h));
            TunnelObs {
                name: h.name.clone(),
                lifecycle,
                if_index: Some(h.if_index),
                backend: TunnelBackendObs {
                    kind: h.backend.as_str().to_string(),
                    active: true,
                    fallback_used: active_transport
                        .as_ref()
                        .map(|a| a.resolved_transport.fallback)
                        .unwrap_or(false),
                    requested: None,
                },
                peers: vec![],
                stats: TunnelStatsObs {
                    rx_bytes: stats.rx_bytes,
                    tx_bytes: stats.tx_bytes,
                    rx_rate_bps: rx_rate,
                    tx_rate_bps: tx_rate,
                    rx_packets: None,
                    tx_packets: None,
                    last_handshake_secs_ago: stats.last_handshake_secs_ago,
                    peer_count: stats.peer_count,
                },
            }
        })
    } else {
        None
    };

    let transport = if want("transport") {
        active_transport.as_ref().map(|a| {
            let tr = obs.transport_recovery.lock().unwrap();
            TransportObs {
                kind: a.transport_session.kind.as_str().to_string(),
                active: true,
                fallback_used: a.resolved_transport.fallback,
                health: tr.last_transport_health.clone(),
                local_endpoint: Some(a.transport_session.wireguard_endpoint.to_string()),
                remote_transport: a.transport_session.remote_transport.map(|x| x.to_string()),
                protocol_version: Some(a.transport_session.protocol_version),
                wire_format: a.transport_session.wire_format.clone(),
                recovery: TransportRecoveryObs {
                    attempts: tr.attempts,
                    max_attempts: tr.max_attempts,
                    last_recovery_at: tr.last_recovery_at.clone(),
                    last_failure_reason: tr.last_failure_reason.clone(),
                },
                extensions: None,
            }
        })
    } else {
        None
    };

    let routing = if want("routing") {
        build_routing(ctx, &cfg).await
    } else {
        RoutingObs::default()
    };

    let network_lock = if want("networkLock") {
        build_network_lock(ctx, &cfg).await
    } else {
        NetworkLockObs {
            configured: cfg.network_lock.enabled,
            active: false,
            wfp_filters: 0,
            violations_blocked: obs
                .violations_blocked
                .load(std::sync::atomic::Ordering::Relaxed),
            last_recovery_at: obs.nl_last_recovery_at.lock().unwrap().clone(),
        }
    };

    let dns = if want("dns") {
        build_dns(ctx, &cfg).await
    } else {
        DnsObs {
            proxy_enabled: cfg.routing.domain_dns.enabled,
            listen: cfg.routing.domain_dns.listen.clone(),
            kernel_redirect: false,
            redirect_active: ctx.domain_mgr.dns_redirect_active(),
            driver: DnsDriverObs {
                present: false,
                ready: false,
                version: None,
            },
            redirect_stats: None,
        }
    };

    let capabilities = if want("capabilities") {
        build_capabilities(ctx).await
    } else {
        CapabilitiesObs {
            schema_version: 3,
            negotiated: json!({}),
        }
    };

    let health = if want("health") {
        compute_health(
            &tunnel,
            &transport,
            &routing,
            &network_lock,
            &dns,
            &session_str,
        )
    } else {
        compute_health(
            &None,
            &None,
            &RoutingObs::default(),
            &NetworkLockObs {
                configured: false,
                active: false,
                wfp_filters: 0,
                violations_blocked: 0,
                last_recovery_at: None,
            },
            &DnsObs {
                proxy_enabled: false,
                listen: "".into(),
                kernel_redirect: false,
                redirect_active: false,
                driver: DnsDriverObs {
                    present: false,
                    ready: false,
                    version: None,
                },
                redirect_stats: None,
            },
            &session_str,
        )
    };

    *obs.last_health.lock().unwrap() = Some(health.clone());

    ObservabilitySnapshot {
        schema_version: OBSERVABILITY_SCHEMA_VERSION,
        ts: obs_now_iso(),
        service: ServiceObs {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: ctx.started_at.elapsed().as_secs(),
            elevated: true,
            session_state: session_str,
        },
        tunnel,
        transport,
        routing,
        network_lock,
        dns,
        capabilities,
        health,
    }
}

async fn build_routing(
    ctx: &ServiceContext,
    cfg: &routeguard_core::config::AppConfig,
) -> RoutingObs {
    let app_total = cfg.routing.app_rules.len();
    let ip_total = cfg.routing.ip_rules.len();
    let domain_total = cfg.routing.domain_rules.len();

    let policy_hash = ctx
        .build_policy()
        .await
        .ok()
        .and_then(|p| serde_json::to_string(&p).ok())
        .map(|s| format!("sha256:{:x}", simple_hash(&s)));

    RoutingObs {
        mode: match cfg.routing.mode {
            RoutingMode::FullTunnel => "full_tunnel".into(),
            RoutingMode::SplitInclude => "split_include".into(),
        },
        app_rules: RuleCountObs {
            total: app_total,
            enabled: app_total,
        },
        ip_rules: RuleCountObs {
            total: ip_total,
            enabled: ip_total,
        },
        domain_rules: RuleCountObs {
            total: domain_total,
            enabled: domain_total,
        },
        domain_routes: DomainRoutesObs {
            active: ctx.domain_mgr.resolved_count(),
            resolved_ips: ctx.domain_mgr.resolved_count(),
            generation: 0,
        },
        compiled_policy_hash: policy_hash,
    }
}

async fn build_network_lock(
    ctx: &ServiceContext,
    cfg: &routeguard_core::config::AppConfig,
) -> NetworkLockObs {
    #[cfg(windows)]
    let active = ctx
        .wfp
        .lock()
        .await
        .as_ref()
        .map(|s| s.network_lock_enabled())
        .unwrap_or(false);
    #[cfg(not(windows))]
    let active = false;

    NetworkLockObs {
        configured: cfg.network_lock.enabled,
        active,
        wfp_filters: 0,
        violations_blocked: ctx
            .observability
            .violations_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        last_recovery_at: ctx
            .observability
            .nl_last_recovery_at
            .lock()
            .unwrap()
            .clone(),
    }
}

async fn build_dns(ctx: &ServiceContext, cfg: &routeguard_core::config::AppConfig) -> DnsObs {
    #[cfg(windows)]
    let (kernel_redirect, redirect_stats, driver_present, driver_ready, driver_version) = {
        let mgr = ctx.dns_callout.lock().await;
        (
            mgr.kernel_active(),
            mgr.get_stats()
                .ok()
                .map(|s| serde_json::to_value(s).unwrap_or(json!({}))),
            mgr.driver_present(),
            mgr.driver_present(),
            None::<String>,
        )
    };
    #[cfg(not(windows))]
    let (kernel_redirect, redirect_stats, driver_present, driver_ready, driver_version) =
        (false, None, false, false, None);

    DnsObs {
        proxy_enabled: cfg.routing.domain_dns.enabled,
        listen: cfg.routing.domain_dns.listen.clone(),
        kernel_redirect,
        redirect_active: ctx.domain_mgr.dns_redirect_active(),
        driver: DnsDriverObs {
            present: driver_present,
            ready: driver_ready,
            version: driver_version,
        },
        redirect_stats,
    }
}

async fn build_capabilities(ctx: &ServiceContext) -> CapabilitiesObs {
    let cfg = ctx.orchestrator.get_config().await;
    let has_domain = !cfg.routing.domain_rules.is_empty();
    let dns_on = cfg.routing.domain_dns.enabled;
    let connected = ctx.has_active_tunnel().await;
    let effective = ctx.domain_mgr.is_effective(has_domain, dns_on, connected);

    #[cfg(windows)]
    let (awg, phantun, lwo, callout) = (
        ctx.selector.probe_awg(),
        ctx.transport_selector.probe_phantun(),
        ctx.transport_selector.probe_lwo(),
        routeguard_wfp::probe_callout_driver(),
    );
    #[cfg(not(windows))]
    let (awg, phantun, lwo, callout) = (false, false, false, false);

    CapabilitiesObs {
        schema_version: 3,
        negotiated: json!({
            "awg": awg,
            "phantun": phantun,
            "lwo": lwo,
            "calloutDriver": callout,
            "domainRoutingEffective": effective,
            "transports": true,
        }),
    }
}

fn session_state_str(s: &SessionState) -> String {
    match s {
        SessionState::Disconnected => "disconnected".into(),
        SessionState::Connecting => "connecting".into(),
        SessionState::Connected => "connected".into(),
        SessionState::Disconnecting => "disconnecting".into(),
        SessionState::Reconnecting => "reconnecting".into(),
        SessionState::Error => "error".into(),
        SessionState::LockedDown => "locked_down".into(),
    }
}

fn simple_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

pub fn transport_health_str(h: TransportHealth) -> &'static str {
    match h {
        TransportHealth::Healthy => "healthy",
        TransportHealth::Degraded => "degraded",
        TransportHealth::Failed => "failed",
    }
}

pub fn update_rates(obs: &crate::observability::state::ObservabilityRuntime, stats: &TunnelStats) {
    let mut last_rx = obs.last_rx_bytes.lock().unwrap();
    let mut last_tx = obs.last_tx_bytes.lock().unwrap();
    let rx_rate = stats.rx_bytes.saturating_sub(*last_rx);
    let tx_rate = stats.tx_bytes.saturating_sub(*last_tx);
    *last_rx = stats.rx_bytes;
    *last_tx = stats.tx_bytes;
    *obs.last_rx_rate.lock().unwrap() = rx_rate;
    *obs.last_tx_rate.lock().unwrap() = tx_rate;
    obs.metrics.record("tunnel.rxRateBps", rx_rate as f64 * 8.0);
    obs.metrics.record("tunnel.txRateBps", tx_rate as f64 * 8.0);
    obs.metrics.record("tunnel.rxBytes", stats.rx_bytes as f64);
    obs.metrics.record("tunnel.txBytes", stats.tx_bytes as f64);
}
