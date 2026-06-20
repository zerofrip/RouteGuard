//! Windows integration tests for application split tunneling.
//!
//! Run elevated with:
//!   set RG_SPLIT_TEST=1
//!   cargo test -p routeguard-platform --test split_tunnel_integration -- --ignored

#![cfg(windows)]

use routeguard_core::config::{AppConfig, AppRule, RuleMode, RoutingMode};
use routeguard_core::policy::PolicySnapshot;
use routeguard_routing::split_policy::AppSplitPolicyCompiler;
use routeguard_routing::{FlowContext, Protocol, RoutingEngine};

fn should_run() -> bool {
    std::env::var("RG_SPLIT_TEST").ok().as_deref() == Some("1")
}

#[test]
#[ignore]
fn test_full_tunnel_exclude_routing_decision() {
    if !should_run() {
        return;
    }
    let mut cfg = AppConfig::default();
    cfg.routing.app_rules.push(AppRule {
        priority: 10,
        mode: RuleMode::Exclude,
        path: r"C:\Windows\System32\curl.exe".into(),
    });
    let engine = RoutingEngine::from_config(&cfg).unwrap();
    let decision = engine.decide(&FlowContext {
        app_path: Some(r"C:\Windows\System32\curl.exe".into()),
        remote_ip: "8.8.8.8".parse().unwrap(),
        remote_port: 443,
        protocol: Protocol::Tcp,
        domain: None,
    });
    assert_eq!(format!("{:?}", decision.target), "Bypass");
}

#[test]
#[ignore]
fn test_split_policy_compiles_bypass_apps() {
    if !should_run() {
        return;
    }
    let mut cfg = AppConfig::default();
    cfg.routing.app_rules.push(AppRule {
        priority: 10,
        mode: RuleMode::Exclude,
        path: r"C:\Program Files\Steam\steam.exe".into(),
    });
    let engine = RoutingEngine::from_config(&cfg).unwrap();
    let snap = AppSplitPolicyCompiler::compile(&cfg, &engine, Some(100), None, Some(5));
    assert_eq!(snap.routing_mode, RoutingMode::FullTunnel);
    assert_eq!(snap.bypass_apps.len(), 1);
}

#[test]
#[ignore]
fn test_split_include_compiles_tunnel_apps() {
    if !should_run() {
        return;
    }
    let mut cfg = AppConfig::default();
    cfg.routing.mode = RoutingMode::SplitInclude;
    cfg.routing.app_rules.push(AppRule {
        priority: 10,
        mode: RuleMode::Include,
        path: r"C:\chrome.exe".into(),
    });
    let engine = RoutingEngine::from_config(&cfg).unwrap();
    let snap = AppSplitPolicyCompiler::compile(&cfg, &engine, Some(100), None, Some(5));
    assert_eq!(snap.tunnel_apps.len(), 1);
    assert!(snap.bypass_apps.is_empty());
}

#[test]
fn test_policy_snapshot_default_fields() {
    let snap = PolicySnapshot::default();
    assert!(snap.tunnel_apps.is_empty());
    assert!(snap.wfp_filter_ids.is_empty());
}
