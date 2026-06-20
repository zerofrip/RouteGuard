//! Compile dynamic domain-resolved hosts into policy CIDR lists.

use ipnet::IpNet;
use routeguard_core::config::RoutingMode;

use crate::domain_store::DomainRouteStore;

pub struct DynamicHostLists {
    pub bypass: Vec<IpNet>,
    pub tunnel: Vec<IpNet>,
}

pub fn compile_dynamic_hosts(store: &DomainRouteStore, mode: RoutingMode) -> DynamicHostLists {
    let bypass_strs = store.dynamic_bypass_hosts();
    let tunnel_strs = store.dynamic_tunnel_hosts();

    let bypass = parse_host_nets(&bypass_strs);
    let tunnel = parse_host_nets(&tunnel_strs);

    let _ = mode; // mode affects install target in SessionRoutes, not list membership
    DynamicHostLists { bypass, tunnel }
}

fn parse_host_nets(cidrs: &[String]) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|s| s.parse::<IpNet>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeguard_core::config::RouteTarget;
    use crate::domain::{DomainRuleEntry};
    use crate::domain_store::DomainRouteStore;

    #[test]
    fn compiles_bypass_and_tunnel() {
        let mut store = DomainRouteStore::default();
        store.apply_resolved(
            "a.example.com",
            &[("1.1.1.1".parse().unwrap(), 300)],
            &DomainRuleEntry {
                priority: 1,
                pattern: "*.example.com".into(),
                target: RouteTarget::Bypass,
            },
        );
        store.apply_resolved(
            "b.example.com",
            &[("2.2.2.2".parse().unwrap(), 300)],
            &DomainRuleEntry {
                priority: 1,
                pattern: "*.other.com".into(),
                target: RouteTarget::Tunnel,
            },
        );
        let lists = compile_dynamic_hosts(&store, RoutingMode::FullTunnel);
        assert_eq!(lists.bypass.len(), 1);
        assert_eq!(lists.tunnel.len(), 1);
    }
}
