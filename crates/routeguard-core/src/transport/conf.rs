//! Runtime `.conf` rewrite and `[RouteGuard]` section parsing.

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::error::{Result, RouteGuardError};
use crate::transport::{
    LwoTransportConfig, PhantunTransportConfig, TransportKind, TransportPreference,
    TunnelTransportConfig,
};

#[derive(Debug, Clone, Default)]
pub struct RouteGuardConfSection {
    pub transport: Option<TransportPreference>,
    pub remote_tcp: Option<String>,
    pub remote_udp: Option<String>,
    pub local_listen: Option<String>,
    pub lwo_enabled: bool,
    pub protocol_version: Option<u8>,
}

pub fn parse_peer_endpoint(conf_text: &str) -> Option<SocketAddr> {
    let mut in_peer = false;
    for line in conf_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_peer = trimmed.eq_ignore_ascii_case("[peer]");
            continue;
        }
        if in_peer && trimmed.to_ascii_lowercase().starts_with("endpoint") {
            if let Some((_, v)) = trimmed.split_once('=') {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

pub fn parse_routeguard_section(conf_text: &str) -> RouteGuardConfSection {
    let mut section = RouteGuardConfSection::default();
    let mut in_rg = false;
    for line in conf_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_rg = trimmed.eq_ignore_ascii_case("[routeguard]");
            continue;
        }
        if !in_rg {
            continue;
        }
        let Some((key, val)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let val = val.trim();
        match key.as_str() {
            "transport" => section.transport = Some(parse_transport_pref(val)),
            "remotetcp" => section.remote_tcp = Some(val.to_string()),
            "remoteudp" => section.remote_udp = Some(val.to_string()),
            "locallisten" => section.local_listen = Some(val.to_string()),
            "lwo" => {
                section.lwo_enabled = matches!(val.to_ascii_lowercase().as_str(), "true" | "1" | "yes");
            }
            "protocolversion" => section.protocol_version = val.parse().ok(),
            _ => {}
        }
    }
    section
}

fn parse_transport_pref(s: &str) -> TransportPreference {
    match s.to_ascii_lowercase().as_str() {
        "phantun" => TransportPreference::Phantun,
        "lwo" => TransportPreference::Lwo,
        "direct_udp" | "direct" | "udp" => TransportPreference::DirectUdp,
        _ => TransportPreference::Auto,
    }
}

pub fn transport_hints_from_conf(conf_text: &str) -> TunnelTransportConfig {
    let rg = parse_routeguard_section(conf_text);
    let mut cfg = TunnelTransportConfig::default();

    if let Some(pref) = rg.transport {
        cfg.preference = pref;
    }

    if rg.remote_tcp.is_some() {
        cfg.phantun = Some(PhantunTransportConfig {
            remote_tcp: rg.remote_tcp.clone(),
            local_listen: rg.local_listen.clone(),
        });
        if matches!(cfg.preference, TransportPreference::Auto) {
            cfg.preference = TransportPreference::Phantun;
        }
    }

    if rg.lwo_enabled
        || rg.remote_udp.is_some()
        || matches!(rg.transport, Some(TransportPreference::Lwo))
    {
        cfg.lwo = Some(LwoTransportConfig {
            remote_udp: rg.remote_udp,
            local_listen: rg.local_listen.clone(),
            protocol_version: rg.protocol_version.unwrap_or(0),
            mode: Some("mullvad".into()),
        });
        if matches!(cfg.preference, TransportPreference::Auto) && rg.remote_tcp.is_none() {
            cfg.preference = TransportPreference::Lwo;
        }
    }

    cfg
}

pub fn merge_transport_config(
    base: &TunnelTransportConfig,
    profile: Option<&TunnelTransportConfig>,
    override_cfg: Option<&TunnelTransportConfig>,
) -> TunnelTransportConfig {
    let mut out = base.clone();
    if let Some(p) = profile {
        if !matches!(p.preference, TransportPreference::Auto) || out.preference == TransportPreference::Auto {
            out.preference = p.preference;
        }
        out.require_phantun |= p.require_phantun;
        out.require_lwo |= p.require_lwo;
        if p.phantun.is_some() {
            out.phantun = p.phantun.clone();
        }
        if p.lwo.is_some() {
            out.lwo = p.lwo.clone();
        }
    }
    if let Some(o) = override_cfg {
        if !matches!(o.preference, TransportPreference::Auto) {
            out.preference = o.preference;
        }
        if o.require_phantun {
            out.require_phantun = true;
        }
        if o.require_lwo {
            out.require_lwo = true;
        }
        if o.phantun.is_some() {
            out.phantun = o.phantun.clone();
        }
        if o.lwo.is_some() {
            out.lwo = o.lwo.clone();
        }
    }
    out
}

pub fn runtime_conf_path(name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("ProgramData") {
            return PathBuf::from(p)
                .join("RouteGuard")
                .join("runtime")
                .join(format!("{name}.conf"));
        }
    }
    PathBuf::from("/var/lib/routeguard/runtime").join(format!("{name}.conf"))
}

pub fn rewrite_conf_endpoint(
    conf_text: &str,
    new_endpoint: SocketAddr,
    mtu: Option<u16>,
) -> Result<String> {
    let mut in_peer = false;
    let mut in_rg = false;
    let mut wrote_endpoint = false;
    let mut wrote_mtu = false;
    let mut out = Vec::new();

    for line in conf_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if in_peer && !wrote_endpoint {
                out.push(format!("Endpoint = {new_endpoint}"));
                wrote_endpoint = true;
            }
            in_rg = trimmed.eq_ignore_ascii_case("[routeguard]");
            in_peer = trimmed.eq_ignore_ascii_case("[peer]");
            if trimmed.eq_ignore_ascii_case("[interface]") {
                wrote_mtu = false;
            }
            if in_rg {
                continue;
            }
            out.push(line.to_string());
            continue;
        }

        if in_rg {
            continue;
        }

        if in_peer && trimmed.to_ascii_lowercase().starts_with("endpoint") {
            out.push(format!("Endpoint = {new_endpoint}"));
            wrote_endpoint = true;
            continue;
        }

        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("transport")
            || lower.starts_with("remotetcp")
            || lower.starts_with("remoteudp")
            || lower.starts_with("locallisten")
            || lower.starts_with("lwo")
            || lower.starts_with("protocolversion")
        {
            continue;
        }

        if lower.starts_with("mtu") {
            if let Some(m) = mtu {
                out.push(format!("MTU = {m}"));
                wrote_mtu = true;
                continue;
            }
        }

        out.push(line.to_string());
    }

    if in_peer && !wrote_endpoint {
        out.push(format!("Endpoint = {new_endpoint}"));
    }

    if let Some(m) = mtu {
        if !wrote_mtu {
            let pos = out
                .iter()
                .position(|l| l.trim().eq_ignore_ascii_case("[interface]"))
                .map(|i| i + 1)
                .unwrap_or(out.len());
            out.insert(pos, format!("MTU = {m}"));
        }
    }

    if out.is_empty() {
        return Err(RouteGuardError::Config("empty conf".into()));
    }

    Ok(out.join("\n") + "\n")
}

pub fn resolve_phantun_remote_tcp(
    cfg: &TunnelTransportConfig,
    peer_endpoint: SocketAddr,
) -> Result<SocketAddr> {
    if let Some(ref p) = cfg.phantun {
        if let Some(ref s) = p.remote_tcp {
            return s
                .parse()
                .map_err(|e| RouteGuardError::Config(format!("invalid remote_tcp: {e}")));
        }
    }
    Ok(peer_endpoint)
}

pub fn resolve_lwo_remote_udp(
    cfg: &TunnelTransportConfig,
    peer_endpoint: SocketAddr,
) -> Result<SocketAddr> {
    if let Some(ref l) = cfg.lwo {
        if let Some(ref s) = l.remote_udp {
            return s
                .parse()
                .map_err(|e| RouteGuardError::Config(format!("invalid remote_udp: {e}")));
        }
    }
    Ok(peer_endpoint)
}

pub fn effective_transport_kind(resolved: TransportKind) -> TransportKind {
    resolved
}

pub fn conf_wants_lwo(conf_text: &str) -> bool {
    let rg = parse_routeguard_section(conf_text);
    rg.lwo_enabled
        || rg.remote_udp.is_some()
        || matches!(rg.transport, Some(TransportPreference::Lwo))
}

pub fn conf_wants_phantun(conf_text: &str) -> bool {
    let rg = parse_routeguard_section(conf_text);
    rg.remote_tcp.is_some() || matches!(rg.transport, Some(TransportPreference::Phantun))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_peer_endpoint_from_conf() {
        let conf = "[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = y\nEndpoint = 1.2.3.4:51820\n";
        let ep = parse_peer_endpoint(conf).unwrap();
        assert_eq!(ep.to_string(), "1.2.3.4:51820");
    }

    #[test]
    fn lwo_section_parsed() {
        let conf = "[RouteGuard]\nTransport = lwo\nRemoteUDP = 203.0.113.1:51820\n";
        let hints = transport_hints_from_conf(conf);
        assert!(matches!(hints.preference, TransportPreference::Lwo));
        assert!(hints.lwo.is_some());
    }

    #[test]
    fn rewrite_strips_routeguard() {
        let conf = "[RouteGuard]\nTransport = lwo\n\n[Interface]\nPrivateKey = x\n\n[Peer]\nEndpoint = 1.2.3.4:51820\nPublicKey = y\n";
        let out = rewrite_conf_endpoint(conf, "127.0.0.1:4567".parse().unwrap(), None).unwrap();
        assert!(!out.to_ascii_lowercase().contains("[routeguard]"));
        assert!(out.contains("127.0.0.1:4567"));
    }
}
