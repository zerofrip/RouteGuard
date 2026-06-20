//! Composite health scoring (0–100).

use serde::{Deserialize, Serialize};

use super::{DnsObs, NetworkLockObs, RoutingObs, TransportObs, TunnelObs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl HealthStatus {
    pub fn from_score(score: u8) -> Self {
        match score {
            90..=100 => HealthStatus::Healthy,
            70..=89 => HealthStatus::Degraded,
            1..=69 => HealthStatus::Unhealthy,
            _ => HealthStatus::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthComponent {
    pub id: String,
    pub score: u8,
    pub status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthReport {
    pub score: u8,
    pub status: HealthStatus,
    pub components: Vec<HealthComponent>,
}

pub fn compute_health(
    tunnel: &Option<TunnelObs>,
    transport: &Option<TransportObs>,
    routing: &RoutingObs,
    network_lock: &NetworkLockObs,
    dns: &DnsObs,
    session_state: &str,
) -> HealthReport {
    let mut components = Vec::new();

    let tunnel_score = score_tunnel(tunnel, session_state);
    components.push(HealthComponent {
        id: "tunnel".into(),
        score: tunnel_score.0,
        status: HealthStatus::from_score(tunnel_score.0),
        reason: tunnel_score.1,
    });

    let transport_score = score_transport(transport, session_state);
    components.push(HealthComponent {
        id: "transport".into(),
        score: transport_score.0,
        status: HealthStatus::from_score(transport_score.0),
        reason: transport_score.1,
    });

    let handshake_score = score_handshake(tunnel);
    components.push(HealthComponent {
        id: "handshake".into(),
        score: handshake_score.0,
        status: HealthStatus::from_score(handshake_score.0),
        reason: handshake_score.1,
    });

    let routing_score = score_routing(routing);
    components.push(HealthComponent {
        id: "routing".into(),
        score: routing_score.0,
        status: HealthStatus::from_score(routing_score.0),
        reason: routing_score.1,
    });

    let domain_score = score_domain(routing, dns);
    components.push(HealthComponent {
        id: "domain".into(),
        score: domain_score.0,
        status: HealthStatus::from_score(domain_score.0),
        reason: domain_score.1,
    });

    let nl_score = score_network_lock(network_lock);
    components.push(HealthComponent {
        id: "networkLock".into(),
        score: nl_score.0,
        status: HealthStatus::from_score(nl_score.0),
        reason: nl_score.1,
    });

    let driver_score = score_driver(dns);
    components.push(HealthComponent {
        id: "driver".into(),
        score: driver_score.0,
        status: HealthStatus::from_score(driver_score.0),
        reason: driver_score.1,
    });

    // Weights: tunnel 25, transport 20, handshake 20, routing 10, domain 10, nl 10, driver 5
    let weighted = if tunnel.is_some() || session_state == "connected" {
        (tunnel_score.0 as u16 * 25
            + transport_score.0 as u16 * 20
            + handshake_score.0 as u16 * 20
            + routing_score.0 as u16 * 10
            + domain_score.0 as u16 * 10
            + nl_score.0 as u16 * 10
            + driver_score.0 as u16 * 5)
            / 100
    } else {
        // Idle: service availability only
        let svc = if session_state == "locked_down" {
            0
        } else {
            100
        };
        svc as u16
    };

    let score = weighted.min(100) as u8;
    HealthReport {
        score,
        status: HealthStatus::from_score(score),
        components,
    }
}

fn score_tunnel(tunnel: &Option<TunnelObs>, session_state: &str) -> (u8, Option<String>) {
    match session_state {
        "connected" => {
            if tunnel.is_some() {
                (100, None)
            } else {
                (80, Some("connected_no_tunnel_obs".into()))
            }
        }
        "connecting" | "reconnecting" => (70, Some(session_state.into())),
        "locked_down" | "error" => (0, Some(session_state.into())),
        _ => (100, None),
    }
}

fn score_transport(transport: &Option<TransportObs>, session_state: &str) -> (u8, Option<String>) {
    if session_state != "connected" {
        return (100, None);
    }
    let Some(t) = transport else {
        return (100, None);
    };
    if t.kind == "direct_udp" {
        return (100, None);
    }
    match t.health.as_str() {
        "healthy" => (100, None),
        "degraded" => (60, Some("transport_degraded".into())),
        "failed" => (0, Some("transport_failed".into())),
        _ => (80, Some("transport_unknown".into())),
    }
}

fn score_handshake(tunnel: &Option<TunnelObs>) -> (u8, Option<String>) {
    let Some(t) = tunnel else {
        return (100, None);
    };
    if t.stats.peer_count == 0 {
        return (50, Some("no_peers".into()));
    }
    let Some(age) = t.stats.last_handshake_secs_ago else {
        return (40, Some("no_handshake".into()));
    };
    if age <= 30 {
        return (100, None);
    }
    if age >= 300 {
        return (0, Some(format!("handshake_age_{age}s")));
    }
    let score = 100u8.saturating_sub(((age * 100) / 300) as u8);
    (
        score,
        if age > 120 {
            Some(format!("handshake_age_{age}s"))
        } else {
            None
        },
    )
}

fn score_routing(_routing: &RoutingObs) -> (u8, Option<String>) {
    (100, None)
}

fn score_domain(routing: &RoutingObs, dns: &DnsObs) -> (u8, Option<String>) {
    if routing.domain_rules.enabled > 0 && !dns.redirect_active && !dns.proxy_enabled {
        return (40, Some("domain_rules_no_ingress".into()));
    }
    if dns.kernel_redirect && !dns.driver.present {
        return (30, Some("driver_missing".into()));
    }
    if dns.driver.present && !dns.driver.ready {
        return (40, Some("driver_not_ready".into()));
    }
    (100, None)
}

fn score_network_lock(nl: &NetworkLockObs) -> (u8, Option<String>) {
    if nl.configured && !nl.active {
        return (50, Some("nl_configured_not_active".into()));
    }
    if nl.violations_blocked > 10 {
        return (60, Some("violation_storm".into()));
    }
    (100, None)
}

fn score_driver(dns: &DnsObs) -> (u8, Option<String>) {
    if !dns.kernel_redirect {
        return (100, None);
    }
    if dns.driver.present && dns.driver.ready {
        return (100, None);
    }
    if dns.driver.present {
        return (40, Some("driver_not_ready".into()));
    }
    (0, Some("driver_absent".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{DnsDriverObs, TunnelBackendObs, TunnelStatsObs};

    fn sample_tunnel(age: u64) -> TunnelObs {
        TunnelObs {
            name: "t".into(),
            lifecycle: "connected".into(),
            if_index: Some(1),
            backend: TunnelBackendObs {
                kind: "wireguard_nt".into(),
                active: true,
                fallback_used: false,
                requested: None,
            },
            peers: vec![],
            stats: TunnelStatsObs {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_rate_bps: 0,
                tx_rate_bps: 0,
                rx_packets: None,
                tx_packets: None,
                last_handshake_secs_ago: Some(age),
                peer_count: 1,
            },
        }
    }

    #[test]
    fn handshake_degrades_with_age() {
        let t = Some(sample_tunnel(150));
        let h = compute_health(
            &t,
            &None,
            &RoutingObs::default(),
            &NetworkLockObs {
                configured: false,
                active: false,
                wfp_filters: 0,
                violations_blocked: 0,
                last_recovery_at: None,
            },
            &DnsObs {
                proxy_enabled: false,
                listen: "".into(),
                kernel_redirect: false,
                redirect_active: false,
                driver: DnsDriverObs {
                    present: false,
                    ready: false,
                    version: None,
                },
                redirect_stats: None,
            },
            "connected",
        );
        let hs = h.components.iter().find(|c| c.id == "handshake").unwrap();
        assert!(hs.score < 100);
    }
}
