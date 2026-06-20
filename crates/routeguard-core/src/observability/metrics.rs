//! Metric descriptors and time-series points.

use serde::{Deserialize, Serialize};

pub const KNOWN_METRICS: &[&str] = &[
    "tunnel.rxRateBps",
    "tunnel.txRateBps",
    "tunnel.rxBytes",
    "tunnel.txBytes",
    "transport.recoveryAttempts",
    "dns.redirectErrors",
    "networkLock.violations",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricDescriptor {
    pub name: String,
    pub unit: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricSeriesPoint {
    pub ts: String,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricSeries {
    pub metric: String,
    pub points: Vec<MetricSeriesPoint>,
}

pub fn list_metrics() -> Vec<MetricDescriptor> {
    KNOWN_METRICS
        .iter()
        .map(|name| MetricDescriptor {
            name: (*name).into(),
            unit: if name.contains("Rate") {
                "bps".into()
            } else if name.contains("Bytes") {
                "bytes".into()
            } else {
                "count".into()
            },
            description: format!("RouteGuard metric {name}"),
        })
        .collect()
}
