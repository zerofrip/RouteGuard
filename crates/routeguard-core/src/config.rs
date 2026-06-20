use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::transport::TunnelTransportConfig;

/// Top-level persisted configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub tunnel: Option<TunnelConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub network_lock: NetworkLockConfig,
}

/// WireGuard tunnel definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub name: String,
    /// Path to `.conf` file or DPAPI-encrypted config.
    pub config_path: PathBuf,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub backend: crate::backend::TunnelBackendPreference,
    #[serde(default)]
    pub require_awg: bool,
    #[serde(default)]
    pub transport: TunnelTransportConfig,
}

fn default_mtu() -> u16 {
    1420
}

/// Routing policy snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default)]
    pub mode: RoutingMode,
    #[serde(default)]
    pub app_rules: Vec<AppRule>,
    #[serde(default)]
    pub ip_rules: Vec<IpRule>,
    #[serde(default)]
    pub domain_rules: Vec<DomainRule>,
    #[serde(default)]
    pub domain_dns: DomainDnsConfig,
}

/// Domain DNS proxy / redirect settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainDnsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dns_listen")]
    pub listen: String,
    #[serde(default = "default_dns_listen_v6")]
    pub listen_v6: String,
    #[serde(default = "default_dns_upstream")]
    pub upstream: Vec<String>,
    #[serde(default)]
    pub redirect_port_53: bool,
    #[serde(default)]
    pub kernel_redirect: bool,
    #[serde(default)]
    pub explicit_proxy: bool,
    #[serde(default = "default_min_ttl")]
    pub min_ttl_secs: u32,
    #[serde(default = "default_max_ttl")]
    pub max_ttl_secs: u32,
    #[serde(default = "default_max_resolved")]
    pub max_resolved_ips: usize,
    #[serde(default = "default_max_domains")]
    pub max_domains: usize,
}

impl Default for DomainDnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_dns_listen(),
            listen_v6: default_dns_listen_v6(),
            upstream: default_dns_upstream(),
            redirect_port_53: false,
            kernel_redirect: false,
            explicit_proxy: false,
            min_ttl_secs: default_min_ttl(),
            max_ttl_secs: default_max_ttl(),
            max_resolved_ips: default_max_resolved(),
            max_domains: default_max_domains(),
        }
    }
}

fn default_dns_listen() -> String {
    "127.0.0.1:5353".into()
}

fn default_dns_listen_v6() -> String {
    "[::1]:5353".into()
}

fn default_dns_upstream() -> Vec<String> {
    vec!["1.1.1.1:53".into(), "[2606:4700:4700::1111]:53".into()]
}

fn default_min_ttl() -> u32 {
    30
}

fn default_max_ttl() -> u32 {
    3600
}

fn default_max_resolved() -> usize {
    50_000
}

fn default_max_domains() -> usize {
    10_000
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            mode: RoutingMode::FullTunnel,
            app_rules: Vec::new(),
            ip_rules: Vec::new(),
            domain_rules: Vec::new(),
            domain_dns: DomainDnsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    #[default]
    FullTunnel,
    SplitInclude,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRule {
    pub priority: u16,
    pub mode: RuleMode,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRule {
    pub priority: u16,
    pub cidr: String,
    pub target: RouteTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRule {
    pub priority: u16,
    pub pattern: String,
    pub target: RouteTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    Include,
    Exclude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTarget {
    Tunnel,
    Bypass,
    Block,
}

/// Network lock (kill switch) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLockConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub allow_lan: bool,
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

impl Default for NetworkLockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_lan: true,
            dns_servers: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

impl AppConfig {
    pub fn from_toml(s: &str) -> crate::Result<Self> {
        toml::from_str(s).map_err(Into::into)
    }

    pub fn to_toml(&self) -> crate::Result<String> {
        toml::to_string_pretty(self).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrip() {
        let cfg = AppConfig::default();
        let s = cfg.to_toml().unwrap();
        let parsed = AppConfig::from_toml(&s).unwrap();
        assert_eq!(parsed.routing.mode, RoutingMode::FullTunnel);
    }
}
