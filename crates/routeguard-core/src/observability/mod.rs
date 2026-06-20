//! Observability types — snapshots, health scoring, metrics descriptors.

mod health;
mod metrics;

pub use health::{compute_health, HealthComponent, HealthReport, HealthStatus};
pub use metrics::{list_metrics, MetricDescriptor, MetricSeries, MetricSeriesPoint, KNOWN_METRICS};

use serde::{Deserialize, Serialize};

pub const OBSERVABILITY_SCHEMA_VERSION: u32 = 1;

/// ISO-8601 UTC timestamp for observability payloads.
pub fn obs_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    format!("{secs}.{millis:03}Z")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservabilitySnapshot {
    pub schema_version: u32,
    pub ts: String,
    pub service: ServiceObs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelObs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportObs>,
    pub routing: RoutingObs,
    pub network_lock: NetworkLockObs,
    pub dns: DnsObs,
    pub capabilities: CapabilitiesObs,
    pub health: HealthReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceObs {
    pub version: String,
    pub uptime_secs: u64,
    pub elevated: bool,
    pub session_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelObs {
    pub name: String,
    pub lifecycle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_index: Option<u32>,
    pub backend: TunnelBackendObs,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerObs>,
    pub stats: TunnelStatsObs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelBackendObs {
    pub kind: String,
    pub active: bool,
    pub fallback_used: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerObs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake_secs_ago: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatsObs {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate_bps: u64,
    pub tx_rate_bps: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake_secs_ago: Option<u64>,
    pub peer_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportObs {
    pub kind: String,
    pub active: bool,
    pub fallback_used: bool,
    pub health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_format: Option<String>,
    pub recovery: TransportRecoveryObs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportRecoveryObs {
    pub attempts: u32,
    pub max_attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_recovery_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_failure_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleCountObs {
    pub total: usize,
    pub enabled: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingObs {
    pub mode: String,
    pub app_rules: RuleCountObs,
    pub ip_rules: RuleCountObs,
    pub domain_rules: RuleCountObs,
    pub domain_routes: DomainRoutesObs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiled_policy_hash: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRoutesObs {
    pub active: usize,
    pub resolved_ips: usize,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkLockObs {
    pub configured: bool,
    pub active: bool,
    pub wfp_filters: u32,
    pub violations_blocked: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_recovery_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsDriverObs {
    pub present: bool,
    pub ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsObs {
    pub proxy_enabled: bool,
    pub listen: String,
    pub kernel_redirect: bool,
    pub redirect_active: bool,
    pub driver: DnsDriverObs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_stats: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesObs {
    pub schema_version: u32,
    pub negotiated: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservabilityHistoryParams {
    pub metric: String,
    #[serde(default = "default_window")]
    pub window: String,
    #[serde(default = "default_resolution")]
    pub resolution: String,
}

fn default_window() -> String {
    "1h".into()
}

fn default_resolution() -> String {
    "auto".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservabilityHistoryResult {
    pub metric: String,
    pub window: String,
    pub resolution: String,
    pub series: Vec<MetricSeriesPoint>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservabilitySnapshotParams {
    #[serde(default)]
    pub sections: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsExportParams {
    #[serde(default = "default_tier")]
    pub tier: String,
    #[serde(default = "default_true")]
    pub include_events: bool,
    #[serde(default = "default_event_limit")]
    pub event_limit: usize,
    #[serde(default = "default_true")]
    pub include_history: bool,
    #[serde(default = "default_history_window")]
    pub history_window: String,
}

fn default_tier() -> String {
    "sanitized".into()
}

fn default_true() -> bool {
    true
}

fn default_event_limit() -> usize {
    500
}

fn default_history_window() -> String {
    "1h".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsExportResult {
    pub bundle_id: String,
    pub path: String,
    pub tier: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsListResult {
    pub metrics: Vec<MetricDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservabilityFeatures {
    pub schema_version: u32,
    pub snapshot_sections: Vec<String>,
    pub history_metrics: Vec<String>,
    pub export_tiers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_report_serializes() {
        let snap = ObservabilitySnapshot {
            schema_version: 1,
            ts: obs_now_iso(),
            service: ServiceObs {
                version: "0.1.0".into(),
                uptime_secs: 1,
                elevated: true,
                session_state: "disconnected".into(),
            },
            tunnel: None,
            transport: None,
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
                listen: "127.0.0.1:5353".into(),
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
                negotiated: serde_json::json!({}),
            },
            health: compute_health(&None, &None, &RoutingObs::default(), &NetworkLockObs {
                configured: false,
                active: false,
                wfp_filters: 0,
                violations_blocked: 0,
                last_recovery_at: None,
            }, &DnsObs {
                proxy_enabled: false,
                listen: "127.0.0.1:5353".into(),
                kernel_redirect: false,
                redirect_active: false,
                driver: DnsDriverObs {
                    present: false,
                    ready: false,
                    version: None,
                },
                redirect_stats: None,
            }, "disconnected"),
        };
        let j = serde_json::to_value(&snap).unwrap();
        assert_eq!(j["schemaVersion"], 1);
    }
}
