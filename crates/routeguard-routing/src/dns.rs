use std::net::IpAddr;

use routeguard_core::config::RouteTarget;
use serde::{Deserialize, Serialize};

/// DNS resolution event feeding dynamic IP rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolvedEvent {
    pub domain: String,
    pub ips: Vec<IpAddr>,
    pub ttl_secs: u32,
}

/// Trait for DNS cache backends (local proxy implements this in platform).
pub trait DnsCache: Send + Sync {
    fn insert(&mut self, event: DnsResolvedEvent);
    fn lookup_domain(&self, domain: &str) -> Option<Vec<IpAddr>>;
    fn lookup_ip(&self, ip: IpAddr) -> Option<RouteTarget>;
}
