use std::net::IpAddr;
use std::path::PathBuf;

use routeguard_core::config::{AppConfig, RouteTarget, RoutingMode};
use serde::{Deserialize, Serialize};

use crate::app::AppRuleSet;
use crate::domain::DomainCache;
use crate::ip::IpRuleTable;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub app_path: Option<PathBuf>,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub target: RouteTarget,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RoutingSnapshot {
    pub mode: RoutingMode,
    pub app_rules: AppRuleSet,
    pub ip_table: IpRuleTable,
    pub domain_cache: DomainCache,
}

impl RoutingSnapshot {
    pub fn from_config(cfg: &AppConfig) -> Result<Self, String> {
        Ok(Self {
            mode: cfg.routing.mode,
            app_rules: AppRuleSet::from_rules(&cfg.routing.app_rules),
            ip_table: IpRuleTable::from_rules(&cfg.routing.ip_rules)?,
            domain_cache: DomainCache::from_rules(&cfg.routing.domain_rules),
        })
    }
}

pub struct RoutingEngine {
    snapshot: RoutingSnapshot,
}

impl RoutingEngine {
    pub fn new(snapshot: RoutingSnapshot) -> Self {
        Self { snapshot }
    }

    pub fn from_config(cfg: &AppConfig) -> Result<Self, String> {
        Ok(Self::new(RoutingSnapshot::from_config(cfg)?))
    }

    pub fn reload(&mut self, snapshot: RoutingSnapshot) {
        self.snapshot = snapshot;
    }

    pub fn on_dns_resolved(&mut self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u32) {
        self.snapshot
            .domain_cache
            .on_resolved(domain, ips, ttl_secs);
    }

    pub fn decide(&self, ctx: &FlowContext) -> RouteDecision {
        // 1. Explicit block (IP, domain, app)
        if let Some(entry) = self.snapshot.ip_table.lookup(ctx.remote_ip) {
            if entry.target == RouteTarget::Block {
                return RouteDecision {
                    target: RouteTarget::Block,
                    reason: format!("ip block rule priority {}", entry.priority),
                };
            }
        }

        if let Some(target) = self.snapshot.domain_cache.lookup_ip(ctx.remote_ip) {
            if target == RouteTarget::Block {
                return RouteDecision {
                    target: RouteTarget::Block,
                    reason: "domain-resolved ip block".into(),
                };
            }
        }

        if let Some(domain) = &ctx.domain {
            if let Some(rule) = self.snapshot.domain_cache.match_domain(domain) {
                if rule.target == RouteTarget::Block {
                    return RouteDecision {
                        target: RouteTarget::Block,
                        reason: format!("domain block {}", rule.pattern),
                    };
                }
            }
        }

        // 2. App rules
        if let Some(app_path) = &ctx.app_path {
            if let Some((mode, pri)) = self
                .snapshot
                .app_rules
                .match_path(app_path, self.snapshot.mode)
            {
                use routeguard_core::config::RuleMode;
                return match (self.snapshot.mode, mode) {
                    (RoutingMode::FullTunnel, RuleMode::Exclude) => RouteDecision {
                        target: RouteTarget::Bypass,
                        reason: format!("app exclude priority {pri}"),
                    },
                    (RoutingMode::SplitInclude, RuleMode::Include) => RouteDecision {
                        target: RouteTarget::Tunnel,
                        reason: format!("app include priority {pri}"),
                    },
                    _ => RouteDecision {
                        target: RouteTarget::Tunnel,
                        reason: "app rule default".into(),
                    },
                };
            }
        }

        // 3. IP bypass/tunnel
        if let Some(entry) = self.snapshot.ip_table.lookup(ctx.remote_ip) {
            return RouteDecision {
                target: entry.target,
                reason: format!("ip rule priority {}", entry.priority),
            };
        }

        if let Some(domain) = &ctx.domain {
            if let Some(rule) = self.snapshot.domain_cache.match_domain(domain) {
                return RouteDecision {
                    target: rule.target,
                    reason: format!("domain rule {}", rule.pattern),
                };
            }
        }

        if let Some(target) = self.snapshot.domain_cache.lookup_ip(ctx.remote_ip) {
            return RouteDecision {
                target,
                reason: "domain-resolved ip".into(),
            };
        }

        // 4. Default
        match self.snapshot.mode {
            RoutingMode::FullTunnel => RouteDecision {
                target: RouteTarget::Tunnel,
                reason: "default full tunnel".into(),
            },
            RoutingMode::SplitInclude => RouteDecision {
                target: RouteTarget::Bypass,
                reason: "default split include bypass".into(),
            },
        }
    }

    pub fn snapshot(&self) -> &RoutingSnapshot {
        &self.snapshot
    }

    pub fn sync_domain_store(&mut self, store: &crate::domain_store::DomainRouteStore) {
        store.sync_domain_cache(&mut self.snapshot.domain_cache);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeguard_core::config::{AppConfig, AppRule, IpRule, RuleMode};

    #[test]
    fn full_tunnel_default() {
        let engine = RoutingEngine::from_config(&AppConfig::default()).unwrap();
        let ctx = FlowContext {
            app_path: None,
            remote_ip: "8.8.8.8".parse().unwrap(),
            remote_port: 443,
            protocol: Protocol::Tcp,
            domain: None,
        };
        assert_eq!(engine.decide(&ctx).target, RouteTarget::Tunnel);
    }

    #[test]
    fn app_exclude_bypass() {
        let mut cfg = AppConfig::default();
        cfg.routing.app_rules.push(AppRule {
            priority: 10,
            mode: RuleMode::Exclude,
            path: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into(),
        });
        let engine = RoutingEngine::from_config(&cfg).unwrap();
        let ctx = FlowContext {
            app_path: Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe".into()),
            remote_ip: "8.8.8.8".parse().unwrap(),
            remote_port: 443,
            protocol: Protocol::Tcp,
            domain: None,
        };
        assert_eq!(engine.decide(&ctx).target, RouteTarget::Bypass);
    }

    #[test]
    fn ip_bypass() {
        let mut cfg = AppConfig::default();
        cfg.routing.ip_rules.push(IpRule {
            priority: 10,
            cidr: "10.0.0.0/8".into(),
            target: RouteTarget::Bypass,
        });
        let engine = RoutingEngine::from_config(&cfg).unwrap();
        let ctx = FlowContext {
            app_path: None,
            remote_ip: "10.1.2.3".parse().unwrap(),
            remote_port: 443,
            protocol: Protocol::Tcp,
            domain: None,
        };
        assert_eq!(engine.decide(&ctx).target, RouteTarget::Bypass);
    }
}
