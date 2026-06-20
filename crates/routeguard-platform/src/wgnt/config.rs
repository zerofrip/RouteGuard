//! Parse WireGuard `.conf` files and serialize to WIREGUARD_INTERFACE buffers.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use ipnet::IpNet;

use super::bindings::{
    socketaddr_to_sockaddr_inet, WIREGUARD_ALLOWED_IP, WIREGUARD_ALLOWED_IP_ADDRESS,
    WIREGUARD_INTERFACE, WIREGUARD_INTERFACE_HAS_LISTEN_PORT, WIREGUARD_INTERFACE_HAS_PRIVATE_KEY,
    WIREGUARD_INTERFACE_REPLACE_PEERS, WIREGUARD_KEY_LENGTH, WIREGUARD_PEER,
    WIREGUARD_PEER_HAS_ENDPOINT, WIREGUARD_PEER_HAS_PRESHARED_KEY,
    WIREGUARD_PEER_HAS_PUBLIC_KEY, WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE,
    WIREGUARD_PEER_REPLACE_ALLOWED_IPS, AF_INET, AF_INET6,
};
use super::error::{WgntError, WgntResult};

#[derive(Debug, Clone, Default)]
pub struct ParsedConf {
    pub private_key: Option<[u8; WIREGUARD_KEY_LENGTH]>,
    pub listen_port: Option<u16>,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u16>,
    pub peers: Vec<ParsedPeer>,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedPeer {
    pub public_key: Option<[u8; WIREGUARD_KEY_LENGTH]>,
    pub preshared_key: Option<[u8; WIREGUARD_KEY_LENGTH]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<u16>,
}

pub fn parse_conf_text(text: &str) -> WgntResult<ParsedConf> {
    let mut conf = ParsedConf::default();
    let mut section = "";

    let mut cur_peer: Option<ParsedPeer> = None;

    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(peer) = cur_peer.take() {
                conf.peers.push(peer);
            }
            section = &line[1..line.len() - 1];
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();

        match section.to_ascii_lowercase().as_str() {
            "interface" => match key.to_ascii_lowercase().as_str() {
                "privatekey" => conf.private_key = Some(decode_key(val)?),
                "listenport" => conf.listen_port = val.parse().ok(),
                "address" => {
                    for addr in val.split(',') {
                        conf.addresses.push(parse_ipnet(addr.trim())?);
                    }
                }
                "dns" => {
                    for dns in val.split(',') {
                        conf.dns.push(dns.trim().parse().map_err(|e| {
                            WgntError::Config(format!("dns: {e}"))
                        })?);
                    }
                }
                "mtu" => conf.mtu = val.parse().ok(),
                _ => {}
            },
            "peer" => {
                let peer = cur_peer.get_or_insert_with(ParsedPeer::default);
                match key.to_ascii_lowercase().as_str() {
                    "publickey" => peer.public_key = Some(decode_key(val)?),
                    "presharedkey" => peer.preshared_key = Some(decode_key(val)?),
                    "endpoint" => peer.endpoint = Some(parse_endpoint(val)?),
                    "allowedips" => {
                        for cidr in val.split(',') {
                            peer.allowed_ips.push(parse_ipnet(cidr.trim())?);
                        }
                    }
                    "persistentkeepalive" => peer.persistent_keepalive = val.parse().ok(),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    if let Some(peer) = cur_peer {
        conf.peers.push(peer);
    }

    if conf.private_key.is_none() {
        return Err(WgntError::Config("missing PrivateKey".into()));
    }

    Ok(conf)
}

pub fn parse_conf_file(path: &Path) -> WgntResult<ParsedConf> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| WgntError::Config(format!("read {}: {e}", path.display())))?;
    parse_conf_text(&text)
}

pub fn serialize_interface(conf: &ParsedConf) -> WgntResult<Vec<u8>> {
    if conf.peers.is_empty() {
        return Err(WgntError::Config("no peers defined".into()));
    }

    let peer_blocks: Vec<(WIREGUARD_PEER, Vec<WIREGUARD_ALLOWED_IP>)> = conf
        .peers
        .iter()
        .map(|p| peer_to_native(p))
        .collect::<WgntResult<Vec<_>>>()?;

    let total_allowed: usize = peer_blocks.iter().map(|(_, a)| a.len()).sum();
    let size = std::mem::size_of::<WIREGUARD_INTERFACE>()
        + peer_blocks.len() * std::mem::size_of::<WIREGUARD_PEER>()
        + total_allowed * std::mem::size_of::<WIREGUARD_ALLOWED_IP>();

    let mut buf = vec![0u8; size];
    let mut flags = WIREGUARD_INTERFACE_REPLACE_PEERS;
    if conf.private_key.is_some() {
        flags |= WIREGUARD_INTERFACE_HAS_PRIVATE_KEY;
    }
    if conf.listen_port.is_some() {
        flags |= WIREGUARD_INTERFACE_HAS_LISTEN_PORT;
    }

    unsafe {
        let iface = buf.as_mut_ptr() as *mut WIREGUARD_INTERFACE;
        (*iface).Flags = flags;
        (*iface).ListenPort = conf.listen_port.unwrap_or(0);
        if let Some(pk) = conf.private_key {
            (*iface).PrivateKey = pk;
        }
        (*iface).PeersCount = peer_blocks.len() as u32;

        let mut offset = std::mem::size_of::<WIREGUARD_INTERFACE>();
        for (peer, allowed) in peer_blocks {
            std::ptr::copy_nonoverlap(
                &peer as *const WIREGUARD_PEER,
                buf.as_mut_ptr().add(offset) as *mut WIREGUARD_PEER,
                1,
            );
            offset += std::mem::size_of::<WIREGUARD_PEER>();
            for aip in allowed {
                std::ptr::copy_nonoverlap(
                    &aip as *const WIREGUARD_ALLOWED_IP,
                    buf.as_mut_ptr().add(offset) as *mut WIREGUARD_ALLOWED_IP,
                    1,
                );
                offset += std::mem::size_of::<WIREGUARD_ALLOWED_IP>();
            }
        }
    }

    Ok(buf)
}

fn peer_to_native(peer: &ParsedPeer) -> WgntResult<(WIREGUARD_PEER, Vec<WIREGUARD_ALLOWED_IP>)> {
    let mut flags = WIREGUARD_PEER_REPLACE_ALLOWED_IPS;
    if peer.public_key.is_some() {
        flags |= WIREGUARD_PEER_HAS_PUBLIC_KEY;
    }
    if peer.preshared_key.is_some() {
        flags |= WIREGUARD_PEER_HAS_PRESHARED_KEY;
    }
    if peer.persistent_keepalive.is_some() {
        flags |= WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE;
    }
    if peer.endpoint.is_some() {
        flags |= WIREGUARD_PEER_HAS_ENDPOINT;
    }

    let endpoint = peer
        .endpoint
        .map(socketaddr_to_sockaddr_inet)
        .map(|(sa, _)| sa)
        .unwrap_or(unsafe { std::mem::zeroed() });

    let wg_peer = WIREGUARD_PEER {
        Flags: flags,
        Reserved: 0,
        PublicKey: peer.public_key.unwrap_or([0; WIREGUARD_KEY_LENGTH]),
        PresharedKey: peer.preshared_key.unwrap_or([0; WIREGUARD_KEY_LENGTH]),
        PersistentKeepalive: peer.persistent_keepalive.unwrap_or(0),
        _padding: 0,
        Endpoint: endpoint,
        TxBytes: 0,
        RxBytes: 0,
        LastHandshake: 0,
        AllowedIPsCount: peer.allowed_ips.len() as u32,
    };

    let allowed = peer
        .allowed_ips
        .iter()
        .map(ipnet_to_allowed_ip)
        .collect::<WgntResult<Vec<_>>>()?;

    Ok((wg_peer, allowed))
}

fn ipnet_to_allowed_ip(net: &IpNet) -> WgntResult<WIREGUARD_ALLOWED_IP> {
    let (family, address) = match net {
        IpNet::V4(v4) => {
            let mut addr = WIREGUARD_ALLOWED_IP_ADDRESS { V4: unsafe { std::mem::zeroed() } };
            unsafe {
                addr.V4.s_addr = u32::from(*v4.addr()).to_be();
            }
            (AF_INET, addr)
        }
        IpNet::V6(v6) => {
            let mut addr = WIREGUARD_ALLOWED_IP_ADDRESS { V6: unsafe { std::mem::zeroed() } };
            unsafe {
                addr.V6.u.Byte = v6.addr().octets();
            }
            (AF_INET6, addr)
        }
    };
    Ok(WIREGUARD_ALLOWED_IP {
        Address: address,
        AddressFamily: family,
        Cidr: net.prefix_len(),
        _padding: 0,
        Flags: 0,
    })
}

fn parse_ipnet(s: &str) -> WgntResult<IpNet> {
    s.parse()
        .map_err(|e| WgntError::Config(format!("invalid cidr {s}: {e}")))
}

fn parse_endpoint(s: &str) -> WgntResult<SocketAddr> {
    if s.starts_with('[') {
        let end = s
            .find(']')
            .ok_or_else(|| WgntError::Config("bad ipv6 endpoint".into()))?;
        let ip: IpAddr = s[1..end]
            .parse()
            .map_err(|e| WgntError::Config(format!("endpoint ip: {e}")))?;
        let port: u16 = s[end + 2..]
            .parse()
            .map_err(|e| WgntError::Config(format!("endpoint port: {e}")))?;
        Ok(SocketAddr::new(ip, port))
    } else {
        s.parse()
            .map_err(|e| WgntError::Config(format!("endpoint: {e}")))
    }
}

fn decode_key(s: &str) -> WgntResult<[u8; WIREGUARD_KEY_LENGTH]> {
    let bytes = decode_b64(s.trim())?;
    if bytes.len() != WIREGUARD_KEY_LENGTH {
        return Err(WgntError::Config("key must be 32 bytes".into()));
    }
    let mut out = [0u8; WIREGUARD_KEY_LENGTH];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_b64(s: &str) -> WgntResult<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.chars() {
        if c == '=' {
            break;
        }
        let val = TABLE
            .iter()
            .position(|&x| x as char == c)
            .ok_or_else(|| WgntError::Config(format!("invalid base64 char {c}")))?
            as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_conf() {
        // 32 zero bytes base64
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let conf = parse_conf_text(&format!(
            r#"
[Interface]
PrivateKey = {key}
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = {key}
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#
        ))
        .unwrap();
        assert_eq!(conf.addresses.len(), 1);
        assert_eq!(conf.peers.len(), 1);
        assert_eq!(conf.peers[0].persistent_keepalive, Some(25));
        let buf = serialize_interface(&conf).unwrap();
        assert!(buf.len() > std::mem::size_of::<WIREGUARD_INTERFACE>());
    }
}
