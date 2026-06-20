use std::net::IpAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelEvent {
    Connecting {
        name: String,
    },
    Connected {
        name: String,
        if_index: u32,
        #[serde(default)]
        backend: crate::backend::BackendKind,
    },
    AwgConnected {
        name: String,
        if_index: u32,
    },
    BackendFallback {
        name: String,
        requested: crate::backend::BackendKind,
        actual: crate::backend::BackendKind,
        reason: String,
    },
    ProfileImported {
        name: String,
        kind: crate::backend::ProfileKind,
    },
    ProfileValidationFailed {
        name: String,
        errors: Vec<String>,
    },
    Disconnecting {
        name: String,
    },
    Disconnected {
        name: String,
        #[serde(default)]
        backend: crate::backend::BackendKind,
    },
    Error {
        name: String,
        message: String,
    },
    Stats {
        name: String,
        rx_bytes: u64,
        tx_bytes: u64,
        #[serde(default)]
        rx_rate_bps: u64,
        #[serde(default)]
        tx_rate_bps: u64,
        #[serde(default)]
        peer_count: usize,
    },
    SessionStateChanged {
        name: String,
        state: String,
    },
    HandshakeThreshold {
        name: String,
        last_handshake_secs_ago: u64,
        peer_count: usize,
    },
    ObservabilityHealthChanged {
        score: u8,
        status: String,
        previous_score: u8,
    },
    TransportHealthChanged {
        kind: crate::transport::TransportKind,
        health: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local_endpoint: Option<String>,
    },
    TransportRecoveryResult {
        kind: crate::transport::TransportKind,
        attempt: u32,
        success: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    DnsRedirectStats {
        stats: serde_json::Value,
    },
    TransportStarting {
        name: String,
        kind: crate::transport::TransportKind,
    },
    TransportConnected {
        name: String,
        kind: crate::transport::TransportKind,
        local_endpoint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remote_transport: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol_version: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wire_format: Option<String>,
    },
    TransportFailed {
        name: String,
        kind: crate::transport::TransportKind,
        reason: String,
        recoverable: bool,
    },
    TransportFallback {
        name: String,
        requested: crate::transport::TransportKind,
        actual: crate::transport::TransportKind,
        reason: String,
    },
    TransportDisconnected {
        name: String,
        kind: crate::transport::TransportKind,
    },
    TransportRecovering {
        name: String,
        kind: crate::transport::TransportKind,
        attempt: u32,
        max_attempts: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingEvent {
    Reloaded {
        rule_count: usize,
    },
    Decision {
        remote_ip: IpAddr,
        target: String,
    },
    DnsResolved {
        domain: String,
        ips: Vec<IpAddr>,
        ttl_secs: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkLockEvent {
    Enabled,
    Disabled,
    Recovered { stale_filters_removed: usize },
    ViolationBlocked { remote_ip: IpAddr },
}

/// Broadcast bus for service-internal events.
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<String>,
}

/// Ring buffer of external-facing events for `events.poll`.
pub struct EventStore {
    next_id: std::sync::atomic::AtomicU64,
    events: std::sync::Mutex<std::collections::VecDeque<EventRecord>>,
    max_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRecord {
    pub id: u64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub ts: String,
    pub payload: serde_json::Value,
}

impl EventStore {
    pub fn new(max_size: usize) -> Self {
        Self {
            next_id: std::sync::atomic::AtomicU64::new(1),
            events: std::sync::Mutex::new(std::collections::VecDeque::new()),
            max_size,
        }
    }

    pub fn push(&self, event_type: impl Into<String>, payload: serde_json::Value) -> u64 {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let record = EventRecord {
            id,
            event_type: event_type.into(),
            ts: chrono_lite_now(),
            payload,
        };
        let mut q = self.events.lock().unwrap();
        q.push_back(record);
        while q.len() > self.max_size {
            q.pop_front();
        }
        id
    }

    pub fn poll(&self, since_id: u64, limit: usize) -> Vec<EventRecord> {
        let q = self.events.lock().unwrap();
        q.iter()
            .filter(|e| e.id > since_id)
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn latest_id(&self) -> u64 {
        self.next_id
            .load(std::sync::atomic::Ordering::SeqCst)
            .saturating_sub(1)
    }
}

fn chrono_lite_now() -> String {
    crate::observability::obs_now_iso()
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    pub fn publish(&self, event: impl Serialize) {
        if let Ok(json) = serde_json::to_string(&event) {
            let _ = self.tx.send(json);
        }
    }

    pub fn now() -> SystemTime {
        SystemTime::now()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(256)
    }
}
