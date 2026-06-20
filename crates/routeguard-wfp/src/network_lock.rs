use std::net::SocketAddr;

use routeguard_core::transport::TransportPermitRule;
use serde::{Deserialize, Serialize};

#[cfg(windows)]
use crate::persistent;

/// Runtime network lock policy applied to WFP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLockPolicy {
    pub enabled: bool,
    pub allow_lan: bool,
    pub dns_servers: Vec<SocketAddr>,
    pub tunnel_if_index: Option<u32>,
    pub endpoint: Option<SocketAddr>,
    /// Extra outbound permits for Phantun TCP (and similar transport helpers).
    #[serde(default)]
    pub transport_permits: Vec<TransportPermitRule>,
}

impl Default for NetworkLockPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_lan: true,
            dns_servers: Vec::new(),
            tunnel_if_index: None,
            endpoint: None,
            transport_permits: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkLockState {
    pub enabled: bool,
    pub active_filter_ids: Vec<u64>,
}

/// WireGuard-aware kill switch via WFP.
pub struct NetworkLock {
    pub(crate) state: NetworkLockState,
}

impl NetworkLock {
    pub fn new() -> Self {
        Self {
            state: NetworkLockState::default(),
        }
    }

    pub fn restore_state(&mut self, state: NetworkLockState) {
        self.state = state;
    }

    pub fn state(&self) -> &NetworkLockState {
        &self.state
    }

    pub fn is_enabled(&self) -> bool {
        self.state.enabled
    }

    #[cfg(windows)]
    pub fn enable(
        &mut self,
        session: &mut super::engine::WfpSessionInner,
        policy: &NetworkLockPolicy,
    ) -> routeguard_core::Result<()> {
        use super::filters;

        if self.state.enabled {
            return Ok(());
        }

        let ids = filters::install_network_lock(session, policy)?;
        self.state.enabled = true;
        self.state.active_filter_ids = ids;
        persistent::save_state(&self.state)?;
        tracing::info!("network lock enabled");
        Ok(())
    }

    #[cfg(windows)]
    pub fn disable(
        &mut self,
        session: &mut super::engine::WfpSessionInner,
    ) -> routeguard_core::Result<()> {
        use super::filters;

        if !self.state.enabled && self.state.active_filter_ids.is_empty() {
            return Ok(());
        }

        filters::remove_filters(session, &self.state.active_filter_ids)?;
        self.state.enabled = false;
        self.state.active_filter_ids.clear();
        persistent::save_state(&self.state)?;
        tracing::info!("network lock disabled");
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn enable(&mut self, _policy: &NetworkLockPolicy) -> routeguard_core::Result<()> {
        Err(routeguard_core::RouteGuardError::UnsupportedPlatform)
    }

    #[cfg(not(windows))]
    pub fn disable(&mut self) -> routeguard_core::Result<()> {
        Err(routeguard_core::RouteGuardError::UnsupportedPlatform)
    }
}

impl Default for NetworkLock {
    fn default() -> Self {
        Self::new()
    }
}
