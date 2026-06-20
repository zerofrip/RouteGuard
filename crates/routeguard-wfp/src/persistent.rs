use std::fs;
use std::path::PathBuf;

use routeguard_core::config::AppRule;
use routeguard_core::error::Result;
use routeguard_core::policy::PolicySnapshot;
use serde::{Deserialize, Serialize};

use crate::network_lock::NetworkLockState;

pub const STATE_DIR: &str = "RouteGuard";
pub const STATE_FILE: &str = "network_lock.json";
pub const APP_RULES_STATE_FILE: &str = "app_rules_state.json";
pub const DNS_REDIRECT_STATE_FILE: &str = "dns_redirect.json";

pub fn dns_redirect_state_path() -> PathBuf {
    state_dir().join(DNS_REDIRECT_STATE_FILE)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsRedirectState {
    pub wfp_filter_ids: Vec<u64>,
    pub kernel_active: bool,
    pub proxy_port: u16,
    pub applied_at: Option<String>,
}

pub fn save_dns_redirect_state(state: &DnsRedirectState) -> Result<()> {
    let path = dns_redirect_state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(state)?)?;
    Ok(())
}

pub fn load_dns_redirect_state() -> Result<Option<DnsRedirectState>> {
    let path = dns_redirect_state_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

pub fn state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("ProgramData") {
            return PathBuf::from(p).join(STATE_DIR);
        }
    }
    PathBuf::from("/var/lib/routeguard")
}

pub fn state_path() -> PathBuf {
    state_dir().join(STATE_FILE)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppRulesState {
    pub rules: Vec<AppRule>,
    pub wfp_filter_ids: Vec<u64>,
    pub tunnel_if_index: Option<u32>,
    pub physical_if_index: Option<u32>,
    pub applied_at: Option<String>,
}

pub fn app_rules_state_path() -> PathBuf {
    state_dir().join(APP_RULES_STATE_FILE)
}

pub fn save_state(state: &NetworkLockState) -> Result<()> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(state)?;
    fs::write(path, data)?;
    Ok(())
}

pub fn load_state() -> Result<NetworkLockState> {
    let path = state_path();
    if !path.exists() {
        return Ok(NetworkLockState::default());
    }
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

pub fn save_session_snapshot(policy: &PolicySnapshot) -> Result<()> {
    let path = state_dir().join("policy_snapshot.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(policy)?;
    fs::write(path, data)?;
    Ok(())
}

pub fn load_session_snapshot() -> Result<Option<PolicySnapshot>> {
    let path = state_dir().join("policy_snapshot.json");
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&data)?))
}

pub fn save_app_rules_state(state: &AppRulesState) -> Result<()> {
    let path = app_rules_state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(state)?;
    fs::write(path, data)?;
    Ok(())
}

pub fn load_app_rules_state() -> Result<Option<AppRulesState>> {
    let path = app_rules_state_path();
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&data)?))
}
