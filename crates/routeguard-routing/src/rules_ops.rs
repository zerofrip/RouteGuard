//! App rule mutation helpers shared by service and CLI validation.

use std::path::{Path, PathBuf};

use routeguard_core::config::{AppConfig, AppRule, RuleMode, RoutingMode};

use crate::app::normalize_path;

pub const MAX_APP_RULES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAppRuleRequest {
    pub path: PathBuf,
    pub mode: RuleMode,
    pub priority: u16,
}

pub fn validate_app_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("app path must be absolute".into());
    }
    let lower = path.to_string_lossy().to_lowercase();
    if !lower.ends_with(".exe") {
        return Err("app path must end with .exe".into());
    }
    if !path.exists() {
        return Err(format!("app path not found: {}", path.display()));
    }
    Ok(path.to_path_buf())
}

pub fn default_priority_for_mode(cfg: &AppConfig, mode: RuleMode) -> u16 {
    cfg.routing
        .app_rules
        .iter()
        .filter(|r| r.mode == mode)
        .map(|r| r.priority)
        .max()
        .unwrap_or(0)
        .saturating_add(10)
}

pub fn add_app_rule(cfg: &mut AppConfig, req: AddAppRuleRequest) -> Result<AppRule, String> {
    if cfg.routing.app_rules.len() >= MAX_APP_RULES {
        return Err(format!("max app rules ({MAX_APP_RULES}) reached"));
    }

    let path = validate_app_path(&req.path)?;
    let normalized = normalize_path(&path);

    if cfg.routing.app_rules.iter().any(|r| normalize_path(&r.path) == normalized) {
        return Err("app rule already exists".into());
    }

    match cfg.routing.mode {
        RoutingMode::FullTunnel if req.mode != RuleMode::Exclude => {
            return Err("full_tunnel mode only supports exclude rules".into());
        }
        RoutingMode::SplitInclude if req.mode != RuleMode::Include => {
            return Err("split_include mode only supports include rules".into());
        }
        _ => {}
    }

    let rule = AppRule {
        priority: req.priority,
        mode: req.mode,
        path,
    };
    cfg.routing.app_rules.push(rule.clone());
    cfg.routing.app_rules.sort_by_key(|r| r.priority);
    Ok(rule)
}

pub fn remove_app_rule(cfg: &mut AppConfig, path: &Path) -> Result<AppRule, String> {
    let normalized = normalize_path(path);
    let idx = cfg
        .routing
        .app_rules
        .iter()
        .position(|r| {
            let rn = normalize_path(&r.path);
            rn == normalized || rn.ends_with(&normalized) || normalized.ends_with(&rn)
        })
        .ok_or_else(|| "app rule not found".to_string())?;
    Ok(cfg.routing.app_rules.remove(idx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_path() {
        assert!(validate_app_path(Path::new("steam.exe")).is_err());
    }
}
