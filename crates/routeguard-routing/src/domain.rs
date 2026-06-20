use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use routeguard_core::config::{DomainRule, RouteTarget};

/// Wildcard domain matcher (`*.example.com`).
pub fn domain_matches(pattern: &str, host: &str) -> bool {
    let host = normalize_domain(host);
    let pattern = pattern.trim_end_matches('.').to_lowercase();

    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        host.ends_with(suffix) && host.len() > suffix.len()
    } else {
        host == pattern || host.ends_with(&format!(".{pattern}"))
    }
}

pub fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Debug, Clone)]
pub struct DomainRuleEntry {
    pub priority: u16,
    pub pattern: String,
    pub target: RouteTarget,
}

#[derive(Debug, Clone)]
pub struct CachedIp {
    pub ips: Vec<IpAddr>,
    pub expires: Instant,
    pub target: RouteTarget,
}

#[derive(Debug, Clone, Default)]
pub struct DomainCache {
    rules: Vec<DomainRuleEntry>,
    resolved: HashMap<String, CachedIp>,
    ip_index: HashMap<IpAddr, RouteTarget>,
}

impl DomainCache {
    pub fn from_rules(rules: &[DomainRule]) -> Self {
        let mut entries: Vec<DomainRuleEntry> = rules
            .iter()
            .map(|r| DomainRuleEntry {
                priority: r.priority,
                pattern: r.pattern.clone(),
                target: r.target,
            })
            .collect();
        entries.sort_by_key(|r| r.priority);
        Self {
            rules: entries,
            resolved: HashMap::new(),
            ip_index: HashMap::new(),
        }
    }

    pub fn match_domain(&self, host: &str) -> Option<&DomainRuleEntry> {
        self.rules
            .iter()
            .filter(|r| domain_matches(&r.pattern, host))
            .min_by_key(|r| r.priority)
    }

    pub fn on_resolved(&mut self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u32) {
        let ttl = Duration::from_secs(u64::from(ttl_secs.max(30)));
        if let Some(rule) = self.match_domain(domain) {
            let target = rule.target;
            for ip in &ips {
                self.ip_index.insert(*ip, target);
            }
            self.resolved.insert(
                normalize_domain(domain),
                CachedIp {
                    ips,
                    expires: Instant::now() + ttl,
                    target,
                },
            );
        }
    }

    pub fn clear_resolved(&mut self) {
        self.resolved.clear();
        self.ip_index.clear();
    }

    pub fn insert_resolved(
        &mut self,
        domain: &str,
        ip: IpAddr,
        target: RouteTarget,
        expires_at_unix: u64,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        if expires_at_unix <= now {
            return;
        }
        let ttl = expires_at_unix - now;
        let expiry = Instant::now() + Duration::from_secs(ttl);
        self.ip_index.insert(ip, target);
        self.resolved
            .entry(normalize_domain(domain))
            .and_modify(|cached| {
                if !cached.ips.contains(&ip) {
                    cached.ips.push(ip);
                }
                cached.expires = expiry;
                cached.target = target;
            })
            .or_insert_with(|| CachedIp {
                ips: vec![ip],
                expires: expiry,
                target,
            });
    }

    pub fn lookup_ip(&self, ip: IpAddr) -> Option<RouteTarget> {
        let now = Instant::now();
        self.ip_index.get(&ip).and_then(|target| {
            // Verify not expired via resolved map
            for cached in self.resolved.values() {
                if cached.expires > now && cached.ips.contains(&ip) {
                    return Some(*target);
                }
            }
            None
        })
    }

    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.resolved.retain(|_, v| v.expires > now);
        self.ip_index.clear();
        for cached in self.resolved.values() {
            for ip in &cached.ips {
                self.ip_index.insert(*ip, cached.target);
            }
        }
    }

    pub fn rules(&self) -> &[DomainRuleEntry] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_match() {
        assert!(domain_matches("*.example.com", "a.example.com"));
        assert!(!domain_matches("*.example.com", "evil-example.com"));
    }

    #[test]
    fn wildcard_local() {
        let cache = DomainCache::from_rules(&[DomainRule {
            priority: 10,
            pattern: "*.local".into(),
            target: RouteTarget::Bypass,
        }]);
        assert!(cache.match_domain("printer.local").is_some());
    }

    #[test]
    fn exact_and_apex() {
        let cache = DomainCache::from_rules(&[DomainRule {
            priority: 10,
            pattern: "example.com".into(),
            target: RouteTarget::Bypass,
        }]);
        assert!(cache.match_domain("example.com").is_some());
        assert!(cache.match_domain("www.example.com").is_some());
    }

    #[test]
    fn resolved_ip_lookup() {
        let mut cache = DomainCache::from_rules(&[DomainRule {
            priority: 10,
            pattern: "*.example.com".into(),
            target: RouteTarget::Bypass,
        }]);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        cache.on_resolved("www.example.com", vec![ip], 60);
        assert_eq!(cache.lookup_ip(ip), Some(RouteTarget::Bypass));
    }
}
