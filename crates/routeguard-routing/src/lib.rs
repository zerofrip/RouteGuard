//! Pure routing decision logic — no OS calls.

pub mod app;
pub mod dns;
pub mod domain;
pub mod domain_policy;
pub mod domain_store;
pub mod engine;
pub mod ip;
pub mod policy;
pub mod rules;
pub mod rules_ops;
pub mod split_policy;

pub use domain_policy::compile_dynamic_hosts;
pub use domain_store::{DomainRouteStore, DomainRouteStoreConfig, ResolvedIpEntry};
pub use engine::{FlowContext, Protocol, RouteDecision, RoutingEngine, RoutingSnapshot};
pub use policy::PolicyCompiler;
pub use rules::RouteTarget;
pub use rules_ops::{
    add_app_rule, default_priority_for_mode, remove_app_rule, validate_app_path, AddAppRuleRequest,
    MAX_APP_RULES,
};
pub use split_policy::AppSplitPolicyCompiler;
