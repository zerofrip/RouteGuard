use routeguard_core::config::{AppConfig, RoutingMode, RuleMode};
use routeguard_core::policy::{AppFilterEntry, PolicySnapshot};

use crate::app::normalize_path;
use crate::domain_store::DomainRouteStore;
use crate::engine::RoutingEngine;

/// Compiles mode-aware split-tunnel policy for WFP and route table.
pub struct AppSplitPolicyCompiler;

impl AppSplitPolicyCompiler {
    pub fn compile(
        cfg: &AppConfig,
        engine: &RoutingEngine,
        tunnel_if_index: Option<u32>,
        tunnel_if_luid: Option<u64>,
        physical_if_index: Option<u32>,
    ) -> PolicySnapshot {
        Self::compile_with_domain_store(cfg, engine, tunnel_if_index, tunnel_if_luid, physical_if_index, None)
    }

    pub fn compile_with_domain_store(
        cfg: &AppConfig,
        engine: &RoutingEngine,
        tunnel_if_index: Option<u32>,
        tunnel_if_luid: Option<u64>,
        physical_if_index: Option<u32>,
        domain_store: Option<&DomainRouteStore>,
    ) -> PolicySnapshot {
        let mut snap = PolicySnapshot::from_config(cfg, tunnel_if_index, tunnel_if_luid);
        snap.physical_if_index = physical_if_index;
        snap.routing_mode = cfg.routing.mode;

        let snapshot = engine.snapshot();
        for cidr in snapshot.ip_table.all_bypass_cidrs() {
            let s = cidr.to_string();
            if !snap.bypass_cidrs.contains(&s) {
                snap.bypass_cidrs.push(s);
            }
        }
        for cidr in snapshot.ip_table.all_block_cidrs() {
            let s = cidr.to_string();
            if !snap.block_cidrs.contains(&s) {
                snap.block_cidrs.push(s);
            }
        }

        for rule in &cfg.routing.app_rules {
            let entry = AppFilterEntry {
                path: normalize_path(&rule.path),
                priority: rule.priority,
                mode: rule.mode,
            };
            match (cfg.routing.mode, rule.mode) {
                (RoutingMode::FullTunnel, RuleMode::Exclude) => {
                    snap.bypass_apps.push(entry.clone());
                    snap.app_permits.push(entry.path.clone());
                }
                (RoutingMode::SplitInclude, RuleMode::Include) => {
                    snap.tunnel_apps.push(entry.clone());
                }
                _ => {}
            }
        }

        if let Some(store) = domain_store {
            snap.dynamic_bypass_hosts = store.dynamic_bypass_hosts();
            snap.dynamic_tunnel_hosts = store.dynamic_tunnel_hosts();
            snap.domain_route_generation = store.generation();
            for cidr in &snap.dynamic_bypass_hosts {
                if !snap.bypass_cidrs.contains(cidr) {
                    snap.bypass_cidrs.push(cidr.clone());
                }
            }
        }

        snap.bypass_apps.sort_by_key(|e| e.priority);
        snap.tunnel_apps.sort_by_key(|e| e.priority);
        snap
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use routeguard_core::config::{AppConfig, AppRule, RuleMode};

    use super::*;
    use crate::engine::RoutingEngine;

    #[test]
    fn full_tunnel_exclude_maps_to_bypass_apps() {
        let mut cfg = AppConfig::default();
        cfg.routing.app_rules.push(AppRule {
            priority: 10,
            mode: RuleMode::Exclude,
            path: r"C:\Program Files\Steam\steam.exe".into(),
        });
        let engine = RoutingEngine::from_config(&cfg).unwrap();
        let snap = AppSplitPolicyCompiler::compile(&cfg, &engine, Some(42), Some(1), Some(5));
        assert_eq!(snap.bypass_apps.len(), 1);
        assert!(snap.bypass_apps[0].path.contains("steam.exe"));
        assert_eq!(snap.app_permits.len(), 1);
        assert!(snap.tunnel_apps.is_empty());
    }

    #[test]
    fn split_include_maps_to_tunnel_apps() {
        let mut cfg = AppConfig::default();
        cfg.routing.mode = RoutingMode::SplitInclude;
        cfg.routing.app_rules.push(AppRule {
            priority: 5,
            mode: RuleMode::Include,
            path: PathBuf::from(r"C:\chrome.exe"),
        });
        let engine = RoutingEngine::from_config(&cfg).unwrap();
        let snap = AppSplitPolicyCompiler::compile(&cfg, &engine, Some(42), None, Some(5));
        assert_eq!(snap.tunnel_apps.len(), 1);
        assert!(snap.bypass_apps.is_empty());
    }
}
