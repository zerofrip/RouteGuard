//! Shared observability runtime state.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use routeguard_core::observability::HealthReport;
use routeguard_core::transport::TransportKind;

use super::logs::LogRing;
use super::store::MetricsStore;

#[derive(Debug, Clone, Default)]
pub struct TransportRecoveryState {
    pub attempts: u32,
    pub max_attempts: u32,
    pub last_recovery_at: Option<String>,
    pub last_failure_reason: Option<String>,
    pub last_transport_health: String,
}

pub struct ObservabilityRuntime {
    pub metrics: MetricsStore,
    pub logs: LogRing,
    pub transport_recovery: Mutex<TransportRecoveryState>,
    pub last_health: Mutex<Option<HealthReport>>,
    pub last_health_score: Mutex<u8>,
    pub violations_blocked: AtomicU64,
    pub nl_last_recovery_at: Mutex<Option<String>>,
    pub last_rx_bytes: Mutex<u64>,
    pub last_tx_bytes: Mutex<u64>,
    pub last_rx_rate: Mutex<u64>,
    pub last_tx_rate: Mutex<u64>,
    pub last_handshake_threshold: Mutex<Option<u64>>,
    pub last_transport_kind_health: Mutex<Option<(TransportKind, String)>>,
}

impl ObservabilityRuntime {
    pub fn new() -> Self {
        Self {
            metrics: MetricsStore::new(),
            logs: LogRing::new(),
            transport_recovery: Mutex::new(TransportRecoveryState {
                max_attempts: 3,
                ..Default::default()
            }),
            last_health: Mutex::new(None),
            last_health_score: Mutex::new(100),
            violations_blocked: AtomicU64::new(0),
            nl_last_recovery_at: Mutex::new(None),
            last_rx_bytes: Mutex::new(0),
            last_tx_bytes: Mutex::new(0),
            last_rx_rate: Mutex::new(0),
            last_tx_rate: Mutex::new(0),
            last_handshake_threshold: Mutex::new(None),
            last_transport_kind_health: Mutex::new(None),
        }
    }

    pub fn record_violation(&self) {
        self.violations_blocked.fetch_add(1, Ordering::Relaxed);
        self.metrics.record(
            "networkLock.violations",
            self.violations_blocked.load(Ordering::Relaxed) as f64,
        );
    }

    pub fn set_transport_health(&self, kind: TransportKind, health: &str) {
        let mut g = self.last_transport_kind_health.lock().unwrap();
        *g = Some((kind, health.to_string()));
        let mut tr = self.transport_recovery.lock().unwrap();
        tr.last_transport_health = health.to_string();
    }

    pub fn record_recovery_attempt(&self, success: bool, reason: Option<String>) {
        let mut tr = self.transport_recovery.lock().unwrap();
        if success {
            tr.attempts = 0;
            tr.last_recovery_at = Some(routeguard_core::observability::obs_now_iso());
            tr.last_failure_reason = None;
        } else {
            tr.attempts = tr.attempts.saturating_add(1);
            tr.last_failure_reason = reason;
            self.metrics
                .record("transport.recoveryAttempts", tr.attempts as f64);
        }
    }
}

pub type SharedObservability = Arc<ObservabilityRuntime>;

pub fn shared() -> SharedObservability {
    Arc::new(ObservabilityRuntime::new())
}
