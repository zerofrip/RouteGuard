use std::net::IpAddr;

use ipnet::IpNet;
use routeguard_core::config::{IpRule, RouteTarget};

#[derive(Debug, Clone)]
pub struct IpRuleEntry {
    pub priority: u16,
    pub cidr: IpNet,
    pub target: RouteTarget,
}

/// Priority-ordered IP rule table with fast CIDR lookup.
#[derive(Debug, Clone, Default)]
pub struct IpRuleTable {
    rules: Vec<IpRuleEntry>,
}

impl IpRuleTable {
    pub fn from_rules(rules: &[IpRule]) -> Result<Self, String> {
        let mut entries = Vec::new();
        for rule in rules {
            let cidr: IpNet = rule
                .cidr
                .parse()
                .map_err(|e| format!("invalid cidr {}: {e}", rule.cidr))?;
            entries.push(IpRuleEntry {
                priority: rule.priority,
                cidr,
                target: rule.target,
            });
        }
        entries.sort_by_key(|r| r.priority);
        Ok(Self { rules: entries })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&IpRuleEntry> {
        self.rules.iter().find(|r| r.cidr.contains(&ip))
    }

    pub fn all_bypass_cidrs(&self) -> Vec<IpNet> {
        self.rules
            .iter()
            .filter(|r| r.target == RouteTarget::Bypass)
            .map(|r| r.cidr)
            .collect()
    }

    pub fn all_block_cidrs(&self) -> Vec<IpNet> {
        self.rules
            .iter()
            .filter(|r| r.target == RouteTarget::Block)
            .map(|r| r.cidr)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_bypass() {
        let table = IpRuleTable::from_rules(&[IpRule {
            priority: 10,
            cidr: "192.168.0.0/16".into(),
            target: RouteTarget::Bypass,
        }])
        .unwrap();
        let hit = table.lookup("192.168.1.1".parse().unwrap()).unwrap();
        assert_eq!(hit.target, RouteTarget::Bypass);
    }
}
