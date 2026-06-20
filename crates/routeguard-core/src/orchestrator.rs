use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::config::AppConfig;
use crate::error::{Result, RouteGuardError};
use crate::events::{EventBus, NetworkLockEvent, TunnelEvent};
use crate::policy::{PolicySnapshot, SessionState};
use crate::tunnel::{TunnelBackend, TunnelHandle, TunnelStatus};

/// Coordinates tunnel, routing policy, and network lock atomically.
pub struct TunnelOrchestrator {
    config: Arc<RwLock<AppConfig>>,
    state: Arc<RwLock<SessionState>>,
    handle: Arc<RwLock<Option<TunnelHandle>>>,
    events: EventBus,
    config_path: PathBuf,
}

impl TunnelOrchestrator {
    pub fn new(config_path: PathBuf, config: AppConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            state: Arc::new(RwLock::new(SessionState::Disconnected)),
            handle: Arc::new(RwLock::new(None)),
            events: EventBus::default(),
            config_path,
        }
    }

    pub fn events(&self) -> &EventBus {
        &self.events
    }

    pub fn config_path(&self) -> &PathBuf {
        &self.config_path
    }

    pub async fn load_config(&self) -> Result<AppConfig> {
        let data = tokio::fs::read_to_string(&self.config_path).await?;
        let cfg = AppConfig::from_toml(&data)?;
        *self.config.write().await = cfg.clone();
        Ok(cfg)
    }

    pub async fn save_config(&self) -> Result<()> {
        let cfg = self.config.read().await;
        let data = cfg.to_toml()?;
        tokio::fs::write(&self.config_path, data).await?;
        Ok(())
    }

    pub async fn get_config(&self) -> AppConfig {
        self.config.read().await.clone()
    }

    pub async fn set_config(&self, cfg: AppConfig) -> Result<()> {
        *self.config.write().await = cfg;
        self.save_config().await
    }

    pub async fn session_state(&self) -> SessionState {
        *self.state.read().await
    }

    pub async fn active_handle(&self) -> Option<TunnelHandle> {
        self.handle.read().await.clone()
    }

    pub async fn connect<B: TunnelBackend>(
        &self,
        backend: &B,
        name: Option<String>,
    ) -> Result<TunnelHandle> {
        let tunnel_cfg = self.tunnel_config_for(name).await?;
        self.begin_connect(&tunnel_cfg.name).await;
        let handle = backend.up(&tunnel_cfg).await?;
        self.complete_connect(handle).await
    }

    async fn tunnel_config_for(&self, name: Option<String>) -> Result<crate::config::TunnelConfig> {
        let cfg = self.config.read().await.clone();
        let tunnel_cfg = cfg
            .tunnel
            .clone()
            .ok_or_else(|| RouteGuardError::Config("no tunnel configured".into()))?;
        let tunnel_name = name.unwrap_or(tunnel_cfg.name.clone());
        let mut tunnel_cfg = tunnel_cfg;
        tunnel_cfg.name = tunnel_name;
        Ok(tunnel_cfg)
    }

    pub async fn begin_connect(&self, name: &str) {
        *self.state.write().await = SessionState::Connecting;
        self.events.publish(TunnelEvent::Connecting {
            name: name.to_string(),
        });
    }

    pub async fn complete_connect(&self, handle: TunnelHandle) -> Result<TunnelHandle> {
        let name = handle.name.clone();
        let if_index = handle.if_index;
        let backend = handle.backend;

        *self.handle.write().await = Some(handle.clone());
        *self.state.write().await = SessionState::Connected;

        if backend == crate::backend::BackendKind::Awg {
            self.events.publish(TunnelEvent::AwgConnected {
                name: name.clone(),
                if_index,
            });
        }

        self.events.publish(TunnelEvent::Connected {
            name,
            if_index,
            backend,
        });

        Ok(handle)
    }

    pub async fn connect_with_handle(&self, handle: TunnelHandle) -> Result<TunnelHandle> {
        self.complete_connect(handle).await
    }

    pub async fn disconnect<B: TunnelBackend>(&self, backend: &B) -> Result<()> {
        let handle = self.handle.read().await.clone();
        let Some(handle) = handle else {
            return Err(RouteGuardError::InvalidState("no active tunnel".into()));
        };

        *self.state.write().await = SessionState::Disconnecting;
        self.events.publish(TunnelEvent::Disconnecting {
            name: handle.name.clone(),
        });

        backend.down(&handle).await?;
        self.clear_handle(handle).await;
        Ok(())
    }

    /// Clear session after backend already disconnected (handler-managed disconnect).
    pub async fn disconnect_with_handle(&self, handle: TunnelHandle) -> Result<()> {
        *self.state.write().await = SessionState::Disconnecting;
        self.clear_handle(handle).await;
        Ok(())
    }

    async fn clear_handle(&self, handle: TunnelHandle) {
        *self.handle.write().await = None;
        *self.state.write().await = SessionState::Disconnected;
        self.events.publish(TunnelEvent::Disconnected {
            name: handle.name,
            backend: handle.backend,
        });
    }

    pub fn build_policy_snapshot(cfg: &AppConfig, handle: Option<&TunnelHandle>) -> PolicySnapshot {
        PolicySnapshot::from_config(cfg, handle.map(|h| h.if_index), handle.map(|h| h.if_luid))
    }

    pub async fn tunnel_status<B: TunnelBackend>(
        &self,
        backend: &B,
    ) -> Result<(TunnelStatus, Option<TunnelHandle>)> {
        let handle = self.handle.read().await.clone();
        let status = match &handle {
            Some(h) => backend.status(h),
            None => TunnelStatus::Disconnected,
        };
        Ok((status, handle))
    }

    pub fn mark_locked_down(&self, state: Arc<RwLock<SessionState>>) {
        tokio::spawn(async move {
            *state.write().await = SessionState::LockedDown;
        });
    }

    pub fn publish_network_lock(&self, event: NetworkLockEvent) {
        self.events.publish(event);
    }
}
