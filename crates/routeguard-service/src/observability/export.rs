//! Diagnostics bundle export.

use std::io::Write;
use std::path::{Path, PathBuf};

use routeguard_core::observability::{
    obs_now_iso, DiagnosticsExportParams, DiagnosticsExportResult, ObservabilitySnapshot,
};
use routeguard_core::Result;
use serde_json::json;
use uuid::Uuid;

use crate::handler::ServiceContext;
use crate::observability::collectors::collect_snapshot;
use crate::observability::store::metrics_dir;

pub async fn export_diagnostics(
    ctx: &ServiceContext,
    params: &DiagnosticsExportParams,
) -> Result<DiagnosticsExportResult> {
    let bundle_id = Uuid::new_v4().to_string();
    let ts = obs_now_iso().replace(':', "-");
    let dir = diagnostics_dir().join(format!("routeguard-diagnostics-{bundle_id}-{ts}"));
    std::fs::create_dir_all(&dir)?;

    let snap = collect_snapshot(ctx, None).await;
    let snap_redacted = redact_snapshot_for_tier(&snap, &params.tier);
    write_json(&dir.join("observability.json"), &snap_redacted)?;

    write_json(&dir.join("health.json"), &snap_redacted.health)?;

    if params.include_history {
        let history_dir = dir.join("history");
        std::fs::create_dir_all(&history_dir)?;
        for metric in ["tunnel.rxRateBps", "tunnel.txRateBps"] {
            let series = ctx
                .observability
                .metrics
                .query(metric, &params.history_window, "auto");
            write_json(
                &history_dir.join(format!("{}.json", metric.replace('.', "-"))),
                &json!({ "metric": metric, "series": series }),
            )?;
        }
    }

    let cfg = ctx.orchestrator.get_config().await;
    let config_toml = config_for_tier(&cfg, &params.tier)?;
    let config_dir = dir.join("config");
    std::fs::create_dir_all(&config_dir)?;
    std::fs::write(config_dir.join("config.sanitized.toml"), config_toml)?;

    write_json(
        &config_dir.join("capabilities.json"),
        &json!({ "capabilities": snap.capabilities }),
    )?;

    write_json(
        &dir.join("routing/rules-summary.json"),
        &json!({ "routing": snap_redacted.routing }),
    )?;

    write_json(
        &dir.join("domain/status.json"),
        &json!({ "dns": snap_redacted.dns }),
    )?;

    if params.include_events {
        let events_dir = dir.join("events");
        std::fs::create_dir_all(&events_dir)?;
        let events = ctx.event_store.poll(0, params.event_limit);
        let mut f = std::fs::File::create(events_dir.join("routeguard-events.ndjson"))?;
        for e in events {
            writeln!(f, "{}", serde_json::to_string(&e)?)?;
        }
    }

    let logs = ctx.observability.logs.tail(200);
    std::fs::create_dir_all(dir.join("logs"))?;
    std::fs::write(dir.join("logs/service-tail.txt"), logs.join("\n"))?;

    let ping = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptimeSecs": ctx.started_at.elapsed().as_secs(),
    });
    std::fs::create_dir_all(dir.join("system"))?;
    write_json(&dir.join("system/routeguard-ping.json"), &ping)?;

    write_json(
        &dir.join("manifest.json"),
        &json!({
            "schemaVersion": 1,
            "bundleId": bundle_id,
            "tier": params.tier,
            "ts": obs_now_iso(),
            "componentVersions": { "routeguard-service": env!("CARGO_PKG_VERSION") },
        }),
    )?;

    let zip_path = dir.with_extension("zip");
    zip_dir(&dir, &zip_path)?;
    let size = std::fs::metadata(&zip_path).map(|m| m.len()).unwrap_or(0);
    let _ = std::fs::remove_dir_all(&dir);

    Ok(DiagnosticsExportResult {
        bundle_id,
        path: zip_path.display().to_string(),
        tier: params.tier.clone(),
        size_bytes: size,
    })
}

fn diagnostics_dir() -> PathBuf {
    metrics_dir()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn config_for_tier(cfg: &routeguard_core::config::AppConfig, tier: &str) -> Result<String> {
    match tier {
        "full" => cfg.to_toml(),
        "support" => {
            let mut c = cfg.clone();
            if let Some(t) = c.tunnel.as_mut() {
                // Keep config path for support tier; plaintext keys never exported.
                if t.config_path.as_os_str().is_empty() {
                    t.config_path = PathBuf::from("<none>");
                }
            }
            c.to_toml()
        }
        _ => sanitize_config(cfg),
    }
}

fn sanitize_config(cfg: &routeguard_core::config::AppConfig) -> Result<String> {
    let mut c = cfg.clone();
    if let Some(t) = c.tunnel.as_mut() {
        t.config_path = PathBuf::from("<redacted>");
    }
    c.to_toml()
}

fn redact_snapshot_for_tier(snap: &ObservabilitySnapshot, tier: &str) -> ObservabilitySnapshot {
    if tier == "full" || tier == "support" {
        return snap.clone();
    }

    let mut out = snap.clone();
    if let Some(ref mut transport) = out.transport {
        transport.remote_transport = Some("<redacted>".into());
        transport.local_endpoint = Some("<redacted>".into());
    }
    if let Some(ref mut tunnel) = out.tunnel {
        for peer in tunnel.peers.iter_mut() {
            peer.public_key = Some("<redacted>".into());
        }
    }
    out
}

fn zip_dir(src: &Path, dst: &Path) -> Result<()> {
    let file = std::fs::File::create(dst)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();

    for path in walkdir(src)? {
        let name = path
            .strip_prefix(src)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        zip.start_file(name, options).map_err(|e| {
            routeguard_core::RouteGuardError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        let data = std::fs::read(&path)?;
        zip.write_all(&data).map_err(|e| {
            routeguard_core::RouteGuardError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
    }
    zip.finish().map_err(|e| {
        routeguard_core::RouteGuardError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;
    Ok(())
}

fn walkdir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if dir.is_dir() {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let p = e.path();
            if p.is_dir() {
                out.extend(walkdir(&p)?);
            } else {
                out.push(p);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use routeguard_core::observability::{
        CapabilitiesObs, DnsDriverObs, DnsObs, HealthReport, HealthStatus, NetworkLockObs,
        ObservabilitySnapshot, RoutingObs, ServiceObs, TransportObs, TransportRecoveryObs,
    };

    use super::*;

    #[test]
    fn support_tier_keeps_transport_remote() {
        let snap = ObservabilitySnapshot {
            schema_version: 1,
            ts: obs_now_iso(),
            service: ServiceObs {
                version: "0.1.0".into(),
                uptime_secs: 1,
                elevated: false,
                session_state: "running".into(),
            },
            tunnel: None,
            transport: Some(TransportObs {
                kind: "direct".into(),
                active: true,
                fallback_used: false,
                health: "healthy".into(),
                local_endpoint: Some("10.0.0.1:51820".into()),
                remote_transport: Some("203.0.113.1:51820".into()),
                protocol_version: None,
                wire_format: None,
                recovery: TransportRecoveryObs {
                    attempts: 0,
                    max_attempts: 3,
                    last_recovery_at: None,
                    last_failure_reason: None,
                },
                extensions: None,
            }),
            routing: RoutingObs::default(),
            network_lock: NetworkLockObs {
                configured: false,
                active: false,
                wfp_filters: 0,
                violations_blocked: 0,
                last_recovery_at: None,
            },
            dns: DnsObs {
                proxy_enabled: false,
                listen: "127.0.0.1:53".into(),
                kernel_redirect: false,
                redirect_active: false,
                driver: DnsDriverObs {
                    present: false,
                    ready: false,
                    version: None,
                },
                redirect_stats: None,
            },
            capabilities: CapabilitiesObs {
                schema_version: 3,
                negotiated: json!({}),
            },
            health: HealthReport {
                score: 100,
                status: HealthStatus::Healthy,
                components: vec![],
            },
        };

        let support = redact_snapshot_for_tier(&snap, "support");
        assert_eq!(
            support
                .transport
                .as_ref()
                .unwrap()
                .remote_transport
                .as_deref(),
            Some("203.0.113.1:51820")
        );

        let sanitized = redact_snapshot_for_tier(&snap, "sanitized");
        assert_eq!(
            sanitized
                .transport
                .as_ref()
                .unwrap()
                .remote_transport
                .as_deref(),
            Some("<redacted>")
        );
    }
}
