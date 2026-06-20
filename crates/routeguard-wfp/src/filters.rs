#[cfg(windows)]
use std::net::SocketAddr;

#[cfg(windows)]
use routeguard_core::error::{Result, RouteGuardError};
#[cfg(windows)]
use routeguard_core::policy::PolicySnapshot;
#[cfg(windows)]
use routeguard_core::transport::{TransportPermitRule, TransportProtocol};
#[cfg(windows)]
use windows_wfp::{Action, Direction, FilterBuilder, FilterRule, FilterWeight};

#[cfg(windows)]
use crate::engine::WfpSessionInner;
#[cfg(windows)]
use crate::ip_mask;
#[cfg(windows)]
use crate::network_lock::NetworkLockPolicy;

#[cfg(windows)]
const PREFIX: &str = "RouteGuard_";

#[cfg(windows)]
pub fn install_network_lock(
    session: &mut WfpSessionInner,
    policy: &NetworkLockPolicy,
) -> Result<Vec<u64>> {
    let mut ids = Vec::new();

    // Block all outbound by default
    let block = FilterRule::new(
        format!("{PREFIX}KS_BLOCK"),
        Direction::Outbound,
        Action::Block,
    )
    .with_weight(FilterWeight::UserBlock);
    let id = FilterBuilder::add_filter(&session.engine, &block)
        .map_err(|e| RouteGuardError::NetworkLock(format!("block filter: {e}")))?;
    ids.push(id);

    // Loopback
    ids.push(add_permit_ip(session, "ALLOW_LOOPBACK_V4", "127.0.0.0/8")?);
    ids.push(add_permit_ip(session, "ALLOW_LOOPBACK_V6", "::1/128")?);

    if policy.allow_lan {
        for (name, cidr) in LAN_CIDRS {
            ids.push(add_permit_ip(session, name, cidr)?);
        }
    }

    for (i, dns) in policy.dns_servers.iter().enumerate() {
        ids.push(add_permit_dns(session, &format!("ALLOW_DNS_{i}"), *dns)?);
    }

    if let Some(ep) = policy.endpoint {
        ids.push(add_permit_endpoint(session, ep)?);
    }

    for (i, permit) in policy.transport_permits.iter().enumerate() {
        ids.push(add_transport_permit(
            session,
            &format!("TRANSPORT_{i}"),
            permit,
        )?);
    }

    Ok(ids)
}

#[cfg(windows)]
pub fn remove_filters(session: &mut WfpSessionInner, ids: &[u64]) -> Result<()> {
    for id in ids {
        FilterBuilder::delete_filter(&session.engine, *id)
            .map_err(|e| RouteGuardError::NetworkLock(format!("delete filter {id}: {e}")))?;
    }
    session.active_filters.retain(|id| !ids.contains(id));
    Ok(())
}

#[cfg(windows)]
pub fn apply_routing_policy(session: &mut WfpSessionInner, policy: &PolicySnapshot) -> Result<()> {
    // Remove prior routing filters tracked on session
    let routing_ids: Vec<u64> = session.active_filters.to_vec();
    for id in routing_ids {
        let _ = FilterBuilder::delete_filter(&session.engine, id);
    }
    session.active_filters.clear();

    for (i, app) in policy.app_permits.iter().enumerate() {
        let rule = FilterRule::new(
            format!("{PREFIX}APP_PERMIT_{i}"),
            Direction::Outbound,
            Action::Permit,
        )
        .with_weight(FilterWeight::UserPermit)
        .with_app_path(app);
        let id = FilterBuilder::add_filter(&session.engine, &rule)
            .map_err(|e| RouteGuardError::Routing(format!("app permit: {e}")))?;
        session.track_filter(id);
    }

    for (i, app) in policy.app_blocks.iter().enumerate() {
        let rule = FilterRule::new(
            format!("{PREFIX}APP_BLOCK_{i}"),
            Direction::Outbound,
            Action::Block,
        )
        .with_weight(FilterWeight::UserBlock)
        .with_app_path(app);
        let id = FilterBuilder::add_filter(&session.engine, &rule)
            .map_err(|e| RouteGuardError::Routing(format!("app block: {e}")))?;
        session.track_filter(id);
    }

    for (i, cidr) in policy.block_cidrs.iter().enumerate() {
        let id = add_block_cidr(session, &format!("IP_BLOCK_{i}"), cidr)?;
        session.track_filter(id);
    }

    Ok(())
}

#[cfg(windows)]
fn add_permit_ip(session: &mut WfpSessionInner, suffix: &str, cidr: &str) -> Result<u64> {
    let rule = FilterRule::new(
        format!("{PREFIX}KS_{suffix}"),
        Direction::Outbound,
        Action::Permit,
    )
    .with_weight(FilterWeight::UserPermit)
    .with_remote_ip(ip_mask::from_str(cidr)?);
    FilterBuilder::add_filter(&session.engine, &rule)
        .map_err(|e| RouteGuardError::NetworkLock(format!("permit {cidr}: {e}")))
}

#[cfg(windows)]
fn add_permit_dns(session: &mut WfpSessionInner, suffix: &str, addr: SocketAddr) -> Result<u64> {
    let rule = FilterRule::new(
        format!("{PREFIX}KS_{suffix}"),
        Direction::Outbound,
        Action::Permit,
    )
    .with_weight(FilterWeight::UserPermit)
    .with_remote_ip(ip_mask::from_ip(addr.ip()))
    .with_protocol(windows_wfp::Protocol::Udp);
    FilterBuilder::add_filter(&session.engine, &rule)
        .map_err(|e| RouteGuardError::NetworkLock(format!("permit dns {addr}: {e}")))
}

#[cfg(windows)]
fn add_transport_permit(
    session: &mut WfpSessionInner,
    suffix: &str,
    permit: &TransportPermitRule,
) -> Result<u64> {
    let proto = match permit.protocol {
        TransportProtocol::Udp => windows_wfp::Protocol::Udp,
        TransportProtocol::Tcp => windows_wfp::Protocol::Tcp,
    };
    let mut rule = FilterRule::new(
        format!("{PREFIX}KS_{suffix}"),
        Direction::Outbound,
        Action::Permit,
    )
    .with_weight(FilterWeight::UserPermit)
    .with_remote_ip(ip_mask::from_ip(permit.remote_ip))
    .with_protocol(proto);
    if let Some(port) = permit.remote_port {
        rule = rule.with_remote_port(port);
    }
    FilterBuilder::add_filter(&session.engine, &rule)
        .map_err(|e| RouteGuardError::NetworkLock(format!("permit transport {permit:?}: {e}")))
}

#[cfg(windows)]
fn add_permit_endpoint(session: &mut WfpSessionInner, ep: SocketAddr) -> Result<u64> {
    let rule = FilterRule::new(
        format!("{PREFIX}KS_ALLOW_EP"),
        Direction::Outbound,
        Action::Permit,
    )
    .with_weight(FilterWeight::UserPermit)
    .with_remote_ip(ip_mask::from_ip(ep.ip()))
    .with_protocol(windows_wfp::Protocol::Udp);
    FilterBuilder::add_filter(&session.engine, &rule)
        .map_err(|e| RouteGuardError::NetworkLock(format!("permit endpoint {ep}: {e}")))
}

#[cfg(windows)]
fn add_block_cidr(session: &mut WfpSessionInner, suffix: &str, cidr: &str) -> Result<u64> {
    let rule = FilterRule::new(
        format!("{PREFIX}{suffix}"),
        Direction::Outbound,
        Action::Block,
    )
    .with_weight(FilterWeight::UserBlock)
    .with_remote_ip(ip_mask::from_str(cidr)?);
    FilterBuilder::add_filter(&session.engine, &rule)
        .map_err(|e| RouteGuardError::Routing(format!("block {cidr}: {e}")))
}

#[cfg(windows)]
const LAN_CIDRS: &[(&str, &str)] = &[
    ("ALLOW_LAN_10", "10.0.0.0/8"),
    ("ALLOW_LAN_172", "172.16.0.0/12"),
    ("ALLOW_LAN_192", "192.168.0.0/16"),
    ("ALLOW_LAN_LLV4", "169.254.0.0/16"),
    ("ALLOW_LAN_LLV6", "fe80::/10"),
    ("ALLOW_LAN_ULA", "fc00::/7"),
];

#[cfg(windows)]
pub fn parse_endpoint_from_config(text: &str) -> Option<SocketAddr> {
    for line in text.lines() {
        let line = line.trim();
        if line.to_ascii_lowercase().starts_with("endpoint") {
            if let Some((_, v)) = line.split_once('=') {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

#[cfg(not(windows))]
pub fn parse_endpoint_from_config(_text: &str) -> Option<std::net::SocketAddr> {
    None
}
