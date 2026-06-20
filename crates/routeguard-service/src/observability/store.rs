//! In-memory metrics ring + rollups.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use routeguard_core::observability::{MetricSeriesPoint, obs_now_iso};

const RAW_CAP: usize = 3600;
const MINUTE_CAP: usize = 1440;

#[derive(Debug, Clone)]
struct Sample {
    ts_secs: u64,
    value: f64,
}

pub struct MetricsStore {
    raw: Mutex<HashMap<String, VecDeque<Sample>>>,
    minute: Mutex<HashMap<String, VecDeque<Sample>>>,
    last_minute_bucket: Mutex<HashMap<String, (u64, f64, u32)>>,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self {
            raw: Mutex::new(HashMap::new()),
            minute: Mutex::new(HashMap::new()),
            last_minute_bucket: Mutex::new(HashMap::new()),
        }
    }

    pub fn record(&self, metric: &str, value: f64) {
        let ts_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        {
            let mut raw = self.raw.lock().unwrap();
            let q = raw.entry(metric.to_string()).or_default();
            q.push_back(Sample { ts_secs, value });
            while q.len() > RAW_CAP {
                q.pop_front();
            }
        }

        {
            let minute_ts = ts_secs / 60;
            let mut buckets = self.last_minute_bucket.lock().unwrap();
            let entry = buckets.entry(metric.to_string()).or_insert((minute_ts, 0.0, 0));
            if entry.0 != minute_ts {
                let (bucket_ts, sum, count) = *entry;
                if count > 0 {
                    let mut minute = self.minute.lock().unwrap();
                    let mq = minute.entry(metric.to_string()).or_default();
                    mq.push_back(Sample {
                        ts_secs: bucket_ts * 60,
                        value: sum / count as f64,
                    });
                    while mq.len() > MINUTE_CAP {
                        mq.pop_front();
                    }
                }
                *entry = (minute_ts, value, 1);
            } else {
                entry.1 += value;
                entry.2 += 1;
            }
        }
    }

    pub fn query(&self, metric: &str, window: &str, resolution: &str) -> Vec<MetricSeriesPoint> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let window_secs = match window {
            "5m" => 300,
            "1h" => 3600,
            "24h" => 86400,
            "7d" => 604800,
            _ => 3600,
        };

        let use_minute = resolution == "1m"
            || resolution == "5m"
            || (resolution == "auto" && window_secs >= 3600);

        let since = now.saturating_sub(window_secs);

        if use_minute {
            let minute = self.minute.lock().unwrap();
            if let Some(q) = minute.get(metric) {
                return q
                    .iter()
                    .filter(|s| s.ts_secs >= since)
                    .map(|s| MetricSeriesPoint {
                        ts: format!("{}Z", s.ts_secs),
                        value: s.value,
                    })
                    .collect();
            }
        }

        let raw = self.raw.lock().unwrap();
        if let Some(q) = raw.get(metric) {
            return q
                .iter()
                .filter(|s| s.ts_secs >= since)
                .map(|s| MetricSeriesPoint {
                    ts: format!("{}Z", s.ts_secs),
                    value: s.value,
                })
                .collect();
        }

        Vec::new()
    }

    pub fn persist_rollups(&self, path: &std::path::Path) {
        let minute = self.minute.lock().unwrap();
        if minute.is_empty() {
            return;
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write;
            for (metric, samples) in minute.iter() {
                if let Some(s) = samples.back() {
                    let line = serde_json::json!({
                        "ts": obs_now_iso(),
                        "metric": metric,
                        "value": s.value,
                    });
                    let _ = writeln!(f, "{line}");
                }
            }
        }
    }
}

impl Default for MetricsStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn metrics_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("ProgramData") {
            return std::path::PathBuf::from(p).join("RouteGuard").join("metrics");
        }
    }
    std::path::PathBuf::from("metrics")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_query() {
        let store = MetricsStore::new();
        store.record("tunnel.rxRateBps", 1000.0);
        store.record("tunnel.rxRateBps", 2000.0);
        let series = store.query("tunnel.rxRateBps", "1h", "1s");
        assert!(!series.is_empty());
    }
}
