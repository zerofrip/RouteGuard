use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::backend::BackendKind;
use crate::config::TunnelConfig;
use crate::error::Result;

/// Opaque handle to an active tunnel session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelHandle {
    pub id: Uuid,
    pub name: String,
    pub if_index: u32,
    pub if_luid: u64,
    #[serde(default)]
    pub backend: BackendKind,
}

/// Full tunnel lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunnelLifecycle {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Error,
}

/// Status reported to clients (alias of lifecycle for IPC compatibility).
pub type TunnelStatus = TunnelLifecycle;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_secs_ago: Option<u64>,
    pub peer_count: usize,
}

/// Platform tunnel backend (WireGuardNT, future AWG).
#[async_trait]
pub trait TunnelBackend: Send + Sync {
    fn name(&self) -> &str;

    async fn up(&self, config: &TunnelConfig) -> Result<TunnelHandle>;

    async fn down(&self, handle: &TunnelHandle) -> Result<()>;

    fn status(&self, handle: &TunnelHandle) -> TunnelStatus;

    fn stats(&self, handle: &TunnelHandle) -> Result<TunnelStats>;

    fn lifecycle(&self, handle: &TunnelHandle) -> TunnelLifecycle {
        self.status(handle)
    }
}
