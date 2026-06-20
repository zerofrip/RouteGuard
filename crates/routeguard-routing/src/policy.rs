use routeguard_core::config::AppConfig;
use routeguard_core::policy::PolicySnapshot;

use crate::engine::RoutingEngine;
use crate::split_policy::AppSplitPolicyCompiler;

/// Compiles routing engine state into WFP/route-table policy.
pub struct PolicyCompiler;

impl PolicyCompiler {
    pub fn compile(
        cfg: &AppConfig,
        engine: &RoutingEngine,
        tunnel_if_index: Option<u32>,
        tunnel_if_luid: Option<u64>,
        physical_if_index: Option<u32>,
    ) -> PolicySnapshot {
        Self::compile_with_domain_store(
            cfg,
            engine,
            tunnel_if_index,
            tunnel_if_luid,
            physical_if_index,
            None,
        )
    }

    pub fn compile_with_domain_store(
        cfg: &AppConfig,
        engine: &RoutingEngine,
        tunnel_if_index: Option<u32>,
        tunnel_if_luid: Option<u64>,
        physical_if_index: Option<u32>,
        domain_store: Option<&crate::domain_store::DomainRouteStore>,
    ) -> PolicySnapshot {
        AppSplitPolicyCompiler::compile_with_domain_store(
            cfg,
            engine,
            tunnel_if_index,
            tunnel_if_luid,
            physical_if_index,
            domain_store,
        )
    }

    pub fn compile_from_config(
        cfg: &AppConfig,
        tunnel_if_index: Option<u32>,
        tunnel_if_luid: Option<u64>,
    ) -> Result<PolicySnapshot, String> {
        let engine = RoutingEngine::from_config(cfg)?;
        Ok(Self::compile(
            cfg,
            &engine,
            tunnel_if_index,
            tunnel_if_luid,
            None,
        ))
    }
}

pub fn reload_engine(cfg: &AppConfig) -> Result<(RoutingEngine, PolicySnapshot), String> {
    let engine = RoutingEngine::from_config(cfg)?;
    let snap = PolicyCompiler::compile(cfg, &engine, None, None, None);
    Ok((engine, snap))
}
