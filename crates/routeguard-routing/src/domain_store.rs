//! TTL-aware domain resolution store with O(1) IP lookup and persistence.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use routeguard_core::config::{DomainRule, RouteTarget};
use serde::{Deserialize, Serialize};

use crate::domain::{domain_matches, normalize_domain, DomainCache, DomainRuleEntry};

const DEFAULT_MAX_RESOLVED_IPS: usize = 50_000;
const DEFAULT_MAX_DOMAINS: usize = 10_000;
const DEFAULT_MIN_TTL_SECS: u32 = 30;
const DEFAULT_MAX_TTL_SECS: u32 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedIpEntry {
    pub ip: IpAddr,
    pub domain: String,
    pub pattern: String,
    pub target: RouteTarget,
    pub expires_at: u64,
    pub ttl_secs: u32,
}

#[derive(Debug, Clone)]
pub struct DomainRouteStoreConfig {
    pub max_resolved_ips: usize,
    pub max_domains: usize,
    pub min_ttl_secs: u32,
    pub max_ttl_secs: u32,
}

impl Default for DomainRouteStoreConfig {
    fn default() -> Self {
        Self {
            max_resolved_ips: DEFAULT_MAX_RESOLVED_IPS,
            max_domains: DEFAULT_MAX_DOMAINS,
            min_ttl_secs: DEFAULT_MIN_TTL_SECS,
            max_ttl_secs: DEFAULT_MAX_TTL_SECS,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ApplyDiff {
    pub added: Vec<ResolvedIpEntry>,
    pub removed: Vec<ResolvedIpEntry>,
    pub refreshed: Vec<ResolvedIpEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct DomainRouteStore {
    rules: Vec<DomainRuleEntry>,
    by_ip: HashMap<IpAddr, ResolvedIpEntry>,
    by_domain: HashMap<String, HashSet<IpAddr>>,
    generation: u64,
    config: DomainRouteStoreConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDomainCache {
    version: u32,
    generation: u64,
    entries: Vec<ResolvedIpEntry>,
}

impl DomainRouteStore {
    pub fn new(config: DomainRouteStoreConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn with_rules(rules: &[DomainRule], config: DomainRouteStoreConfig) -> Self {
        let mut store = Self::new(config);
        store.set_rules(rules);
        store
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn bump_generation(&mut self) {
        self.generation = self.generation.saturating_add(1);
    }

    pub fn set_rules(&mut self, rules: &[DomainRule]) {
        self.rules = rules
            .iter()
            .map(|r| DomainRuleEntry {
                priority: r.priority,
                pattern: r.pattern.clone(),
                target: r.target,
            })
            .collect();
        self.rules.sort_by_key(|r| r.priority);
        self.bump_generation();
    }

    pub fn rules(&self) -> &[DomainRuleEntry] {
        &self.rules
    }

    pub fn match_domain(&self, domain: &str) -> Option<&DomainRuleEntry> {
        let d = normalize_domain(domain);
        self.rules
            .iter()
            .filter(|r| domain_matches(&r.pattern, &d))
            .min_by_key(|r| r.priority)
    }

    pub fn lookup_ip(&self, ip: IpAddr) -> Option<RouteTarget> {
        let entry = self.by_ip.get(&ip)?;
        if entry.expires_at <= now_unix() {
            return None;
        }
        Some(entry.target)
    }

    pub fn entry_for_ip(&self, ip: IpAddr) -> Option<&ResolvedIpEntry> {
        let entry = self.by_ip.get(&ip)?;
        if entry.expires_at <= now_unix() {
            return None;
        }
        Some(entry)
    }

    pub fn resolved_count(&self) -> usize {
        self.by_ip.len()
    }

    pub fn domain_count(&self) -> usize {
        self.by_domain.len()
    }

    pub fn entries(&self) -> impl Iterator<Item = &ResolvedIpEntry> {
        self.by_ip.values()
    }

    /// Apply DNS resolution for a domain that already matched a rule.
    pub fn apply_resolved(
        &mut self,
        domain: &str,
        ips: &[(IpAddr, u32)],
        rule: &DomainRuleEntry,
    ) -> ApplyDiff {
        let domain = normalize_domain(domain);
        let mut diff = ApplyDiff::default();
        let now = now_unix();

        let config = self.config.clone();
        let resolved: Vec<(IpAddr, u32, u64)> = ips
            .iter()
            .map(|(ip, ttl)| {
                let ttl = clamp_ttl(*ttl, &config);
                (*ip, ttl, now + u64::from(ttl))
            })
            .collect();

        let new_ips: HashSet<IpAddr> = resolved.iter().map(|(ip, _, _)| *ip).collect();

        let previous: HashSet<IpAddr> = self
            .by_domain
            .get(&domain)
            .cloned()
            .unwrap_or_default();

        for ip in previous.difference(&new_ips) {
            if let Some(entry) = self.remove_ip(*ip) {
                diff.removed.push(entry);
            }
        }

        for (ip, ttl, expires_at) in resolved {
            if let Some(existing) = self.by_ip.get(&ip) {
                if existing.domain == domain
                    && existing.pattern == rule.pattern
                    && existing.target == rule.target
                {
                    let mut updated = existing.clone();
                    updated.ttl_secs = ttl;
                    updated.expires_at = expires_at;
                    self.by_ip.insert(ip, updated.clone());
                    diff.refreshed.push(updated);
                    continue;
                }
            }

            let entry = ResolvedIpEntry {
                ip,
                domain: domain.clone(),
                pattern: rule.pattern.clone(),
                target: rule.target,
                expires_at,
                ttl_secs: ttl,
            };
            self.insert_entry(entry.clone());
            diff.added.push(entry);
        }

        if diff.added.is_empty() && diff.removed.is_empty() && diff.refreshed.is_empty() {
            // Ensure domain index exists even on no-op TTL-only refresh batch
            self.by_domain.entry(domain).or_default();
        }

        diff
    }

    fn insert_entry(&mut self, entry: ResolvedIpEntry) {
        let ip = entry.ip;
        let domain = entry.domain.clone();
        if let Some(old) = self.by_ip.insert(ip, entry) {
            if let Some(set) = self.by_domain.get_mut(&old.domain) {
                set.remove(&ip);
                if set.is_empty() {
                    self.by_domain.remove(&old.domain);
                }
            }
        }
        self.by_domain.entry(domain).or_default().insert(ip);
        self.enforce_caps();
    }

    fn remove_ip(&mut self, ip: IpAddr) -> Option<ResolvedIpEntry> {
        let entry = self.by_ip.remove(&ip)?;
        if let Some(set) = self.by_domain.get_mut(&entry.domain) {
            set.remove(&ip);
            if set.is_empty() {
                self.by_domain.remove(&entry.domain);
            }
        }
        Some(entry)
    }

    pub fn purge_expired(&mut self) -> Vec<ResolvedIpEntry> {
        let now = now_unix();
        let expired: Vec<IpAddr> = self
            .by_ip
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(ip, _)| *ip)
            .collect();
        expired
            .into_iter()
            .filter_map(|ip| self.remove_ip(ip))
            .collect()
    }

    pub fn clear(&mut self) {
        self.by_ip.clear();
        self.by_domain.clear();
        self.bump_generation();
    }

    /// Drop entries whose pattern no longer matches any current rule.
    pub fn prune_unmatched_rules(&mut self) -> Vec<ResolvedIpEntry> {
        let stale: Vec<IpAddr> = self
            .by_ip
            .iter()
            .filter(|(_, e)| {
                !self
                    .rules
                    .iter()
                    .any(|r| r.pattern == e.pattern && r.target == e.target)
            })
            .map(|(ip, _)| *ip)
            .collect();
        stale
            .into_iter()
            .filter_map(|ip| self.remove_ip(ip))
            .collect()
    }

    pub fn dynamic_bypass_hosts(&self) -> Vec<String> {
        host_cidrs_for_target(self, RouteTarget::Bypass)
    }

    pub fn dynamic_tunnel_hosts(&self) -> Vec<String> {
        host_cidrs_for_target(self, RouteTarget::Tunnel)
    }

    fn enforce_caps(&mut self) {
        while self.by_ip.len() > self.config.max_resolved_ips {
            let oldest = self
                .by_ip
                .iter()
                .min_by_key(|(_, e)| e.expires_at)
                .map(|(ip, _)| *ip);
            if let Some(ip) = oldest {
                self.remove_ip(ip);
            } else {
                break;
            }
        }

        while self.by_domain.len() > self.config.max_domains {
            let victim = self
                .by_domain
                .iter()
                .filter_map(|(name, ips)| {
                    ips.iter()
                        .filter_map(|ip| self.by_ip.get(ip))
                        .map(|e| e.expires_at)
                        .min()
                        .map(|exp| (name.clone(), exp))
                })
                .min_by_key(|(_, exp)| *exp)
                .map(|(name, _)| name);
            if let Some(domain) = victim {
                let ips: Vec<_> = self
                    .by_domain
                    .remove(&domain)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                for ip in ips {
                    self.by_ip.remove(&ip);
                }
            } else {
                break;
            }
        }
    }

    fn to_persisted(&self) -> PersistedDomainCache {
        PersistedDomainCache {
            version: 1,
            generation: self.generation,
            entries: self.by_ip.values().cloned().collect(),
        }
    }

    pub fn load_persisted(json: &str, config: DomainRouteStoreConfig) -> Result<Self, String> {
        let parsed: PersistedDomainCache =
            serde_json::from_str(json).map_err(|e| format!("parse domain cache: {e}"))?;
        if parsed.version != 1 {
            return Err(format!("unsupported domain cache version {}", parsed.version));
        }
        let mut store = Self::new(config);
        store.generation = parsed.generation;
        let now = now_unix();
        for entry in parsed.entries {
            if entry.expires_at > now {
                store.insert_entry(entry);
            }
        }
        Ok(store)
    }

    pub fn persist_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.to_persisted())
            .map_err(|e| format!("serialize domain cache: {e}"))
    }

    /// Sync engine-facing DomainCache resolved map from store (for decide()).
    pub fn sync_domain_cache(&self, cache: &mut DomainCache) {
        cache.clear_resolved();
        let now = now_unix();
        for entry in self.by_ip.values() {
            if entry.expires_at > now {
                cache.insert_resolved(&entry.domain, entry.ip, entry.target, entry.expires_at);
            }
        }
    }
}

fn host_cidrs_for_target(store: &DomainRouteStore, target: RouteTarget) -> Vec<String> {
    let now = now_unix();
    store
        .by_ip
        .values()
        .filter(|e| e.target == target && e.expires_at > now)
        .map(|e| ip_to_host_cidr(e.ip))
        .collect()
}

pub fn ip_to_host_cidr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    }
}

fn clamp_ttl(ttl: u32, config: &DomainRouteStoreConfig) -> u32 {
    ttl.max(config.min_ttl_secs).min(config.max_ttl_secs)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeguard_core::config::DomainRule;

    fn rule(pattern: &str, target: RouteTarget) -> DomainRuleEntry {
        DomainRuleEntry {
            priority: 10,
            pattern: pattern.into(),
            target,
        }
    }

    #[test]
    fn apply_and_lookup() {
        let mut store = DomainRouteStore::default();
        let ip: IpAddr = "149.154.167.99".parse().unwrap();
        let diff = store.apply_resolved(
            "api.netflix.com",
            &[(ip, 300)],
            &rule("*.netflix.com", RouteTarget::Tunnel),
        );
        assert_eq!(diff.added.len(), 1);
        assert_eq!(store.lookup_ip(ip), Some(RouteTarget::Tunnel));
    }

    #[test]
    fn ttl_refresh_keeps_route() {
        let mut store = DomainRouteStore::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let r = rule("*.example.com", RouteTarget::Bypass);
        store.apply_resolved("www.example.com", &[(ip, 60)], &r);
        let diff = store.apply_resolved("www.example.com", &[(ip, 120)], &r);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.refreshed.len(), 1);
        assert_eq!(store.lookup_ip(ip), Some(RouteTarget::Bypass));
    }

    #[test]
    fn ip_removal_on_reresolve() {
        let mut store = DomainRouteStore::default();
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        let r = rule("*.cdn.com", RouteTarget::Tunnel);
        store.apply_resolved("x.cdn.com", &[(ip1, 60), (ip2, 60)], &r);
        let diff = store.apply_resolved("x.cdn.com", &[(ip2, 60)], &r);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].ip, ip1);
        assert!(store.lookup_ip(ip1).is_none());
    }

    #[test]
    fn persistence_roundtrip() {
        let mut store = DomainRouteStore::default();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        store.apply_resolved(
            "dns.google",
            &[(ip, 300)],
            &rule("*.google.com", RouteTarget::Bypass),
        );
        let json = store.persist_json().unwrap();
        let loaded = DomainRouteStore::load_persisted(&json, DomainRouteStoreConfig::default())
            .unwrap();
        assert_eq!(loaded.lookup_ip(ip), Some(RouteTarget::Bypass));
    }

    #[test]
    fn wildcard_local_pattern() {
        let store = DomainRouteStore::with_rules(
            &[DomainRule {
                priority: 5,
                pattern: "*.local".into(),
                target: RouteTarget::Bypass,
            }],
            DomainRouteStoreConfig::default(),
        );
        assert!(store.match_domain("printer.local").is_some());
    }

    #[test]
    fn lru_at_cap() {
        let config = DomainRouteStoreConfig {
            max_resolved_ips: 2,
            ..Default::default()
        };
        let mut store = DomainRouteStore::new(config);
        let r = rule("*.x.com", RouteTarget::Tunnel);
        store.apply_resolved("a.x.com", &[("1.1.1.1".parse().unwrap(), 10)], &r);
        store.apply_resolved("b.x.com", &[("2.2.2.2".parse().unwrap(), 1000)], &r);
        store.apply_resolved("c.x.com", &[("3.3.3.3".parse().unwrap(), 2000)], &r);
        assert_eq!(store.resolved_count(), 2);
        assert!(store.lookup_ip("1.1.1.1".parse().unwrap()).is_none());
    }
}
