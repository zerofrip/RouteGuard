use serde::{Deserialize, Serialize};

use crate::config::{AppConfig, RoutingMode, RuleMode};
use crate::transport::TransportPermitRule;

/// Per-application WFP filter entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppFilterEntry {
    pub path: String,
    pub priority: u16,
    pub mode: RuleMode,
}

/// Compiled policy applied to WFP and route table.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicySnapshot {
    pub routing_mode: RoutingMode,
    pub tunnel_if_index: Option<u32>,
    pub tunnel_if_luid: Option<u64>,
    pub physical_if_index: Option<u32>,
    pub endpoint: Option<String>,
    /// Legacy app permit list (network lock exceptions + bypass apps).
    pub app_permits: Vec<String>,
    /// Legacy app block list.
    pub app_blocks: Vec<String>,
    pub tunnel_apps: Vec<AppFilterEntry>,
    pub bypass_apps: Vec<AppFilterEntry>,
    pub bypass_cidrs: Vec<String>,
    pub block_cidrs: Vec<String>,
    /// Dynamic /32,/128 host routes from domain DNS cache (bypass).
    #[serde(default)]
    pub dynamic_bypass_hosts: Vec<String>,
    /// Dynamic /32,/128 host routes from domain DNS cache (tunnel).
    #[serde(default)]
    pub dynamic_tunnel_hosts: Vec<String>,
    #[serde(default)]
    pub domain_route_generation: u64,
    pub network_lock_enabled: bool,
    pub allow_lan: bool,
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub transport_permits: Vec<TransportPermitRule>,
    pub wfp_filter_ids: Vec<u64>,
}

impl PolicySnapshot {
    pub fn from_config(
        cfg: &AppConfig,
        tunnel_if_index: Option<u32>,
        tunnel_if_luid: Option<u64>,
    ) -> Self {
        let mut snap = PolicySnapshot {
            routing_mode: cfg.routing.mode,
            tunnel_if_index,
            tunnel_if_luid,
            network_lock_enabled: cfg.network_lock.enabled,
            allow_lan: cfg.network_lock.allow_lan,
            dns_servers: cfg.network_lock.dns_servers.clone(),
            ..Default::default()
        };

        for rule in &cfg.routing.ip_rules {
            match rule.target {
                crate::config::RouteTarget::Bypass => snap.bypass_cidrs.push(rule.cidr.clone()),
                crate::config::RouteTarget::Block => snap.block_cidrs.push(rule.cidr.clone()),
                crate::config::RouteTarget::Tunnel => {}
            }
        }

        snap
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Error,
    LockedDown,
}
