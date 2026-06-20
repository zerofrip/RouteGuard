//! Active connect session — transport layer state for disconnect / policy.

use std::path::PathBuf;
use std::sync::Mutex;

use routeguard_core::transport::{PreparedConnect, ResolvedTransport, TransportSession};

use crate::transport_selector::TransportChoice;

#[derive(Debug, Clone)]
pub struct ActiveConnectSession {
    pub tunnel_name: String,
    pub source_config_path: PathBuf,
    pub peer_endpoint: std::net::SocketAddr,
    pub merged_transport: routeguard_core::transport::TunnelTransportConfig,
    pub transport_session: TransportSession,
    pub transport_choice: TransportChoice,
    pub resolved_transport: ResolvedTransport,
    pub runtime_conf_path: PathBuf,
}

impl ActiveConnectSession {
    pub fn from_prepared(
        prepared: PreparedConnect,
        choice: TransportChoice,
        source_config_path: PathBuf,
    ) -> Option<Self> {
        let transport_session = prepared.transport_session?;
        Some(Self {
            tunnel_name: prepared.tunnel_config.name,
            source_config_path,
            peer_endpoint: transport_session.original_endpoint,
            merged_transport: prepared.tunnel_config.transport,
            transport_session,
            transport_choice: choice,
            resolved_transport: prepared.resolved,
            runtime_conf_path: prepared.runtime_conf_path,
        })
    }
}

pub struct ConnectSessionStore {
    inner: Mutex<Option<ActiveConnectSession>>,
}

impl ConnectSessionStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub fn set(&self, session: ActiveConnectSession) {
        *self.inner.lock().unwrap() = Some(session);
    }

    pub fn take(&self) -> Option<ActiveConnectSession> {
        self.inner.lock().unwrap().take()
    }

    pub fn active(&self) -> Option<ActiveConnectSession> {
        self.inner.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        *self.inner.lock().unwrap() = None;
    }
}

impl Default for ConnectSessionStore {
    fn default() -> Self {
        Self::new()
    }
}
