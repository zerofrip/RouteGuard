//! DNS interceptor / proxy for domain-based routing.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use routeguard_core::error::{Result, RouteGuardError};
use routeguard_routing::dns::DnsResolvedEvent;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    pub listen: SocketAddr,
    pub listen_v6: Option<SocketAddr>,
    pub upstream: Vec<SocketAddr>,
    pub min_ttl_secs: u32,
    pub max_ttl_secs: u32,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:5353".parse().unwrap(),
            listen_v6: Some("[::1]:5353".parse().unwrap()),
            upstream: vec!["1.1.1.1:53".parse().unwrap()],
            min_ttl_secs: 30,
            max_ttl_secs: 3600,
        }
    }
}

pub type DnsResponseCallback = Arc<dyn Fn(&str, &[(IpAddr, u32)]) + Send + Sync>;

#[async_trait]
pub trait DnsInterceptor: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    fn listen_addr(&self) -> SocketAddr;
}

/// Local DNS proxy forwarding to upstream; rule-gated caching via callback.
pub struct DnsProxy {
    config: DnsProxyConfig,
    running: Arc<AtomicBool>,
    on_response: DnsResponseCallback,
}

impl DnsProxy {
    pub fn new(config: DnsProxyConfig, on_response: DnsResponseCallback) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            on_response,
        }
    }
}

#[async_trait]
impl DnsInterceptor for DnsProxy {
    async fn start(&self) -> Result<()> {
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        let listen = self.config.listen;
        let listen_v6 = self.config.listen_v6;
        let upstream = self.config.upstream.clone();
        let running = self.running.clone();
        let on_response = self.on_response.clone();
        let min_ttl = self.config.min_ttl_secs;
        let max_ttl = self.config.max_ttl_secs;

        tokio::spawn(async move {
            let v4 = run_dns_socket(listen, upstream.clone(), running.clone(), on_response.clone(), min_ttl, max_ttl);
            let v6 = listen_v6.map(|addr| {
                run_dns_socket(addr, upstream, running.clone(), on_response, min_ttl, max_ttl)
            });

            if let Err(e) = v4.await {
                tracing::error!("DNS proxy v4 error: {e}");
            }
            if let Some(fut) = v6 {
                if let Err(e) = fut.await {
                    tracing::error!("DNS proxy v6 error: {e}");
                }
            }
            running.store(false, Ordering::SeqCst);
        });

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }
}

async fn run_dns_socket(
    listen: SocketAddr,
    upstream: Vec<SocketAddr>,
    running: Arc<AtomicBool>,
    on_response: DnsResponseCallback,
    min_ttl: u32,
    max_ttl: u32,
) -> Result<()> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind(listen)
        .await
        .map_err(|e| RouteGuardError::Dns(format!("bind {listen}: {e}")))?;

    let socket = Arc::new(socket);
    tracing::info!("DNS proxy listening on {listen}");

    let mut buf = [0u8; 512];
    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        let recv = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            socket.recv_from(&mut buf),
        )
        .await;

        let (len, peer) = match recv {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(RouteGuardError::Io(e)),
            Err(_) => continue,
        };

        if !is_loopback_peer(peer) {
            tracing::debug!("DNS proxy rejected non-loopback peer {peer}");
            continue;
        }

        let query = buf[..len].to_vec();
        let upstream_addr = upstream
            .first()
            .copied()
            .unwrap_or_else(|| "1.1.1.1:53".parse().unwrap());

        let sock = socket.clone();
        let cb = on_response.clone();
        tokio::spawn(async move {
            if let Ok(response) = forward_dns(&query, upstream_addr).await {
                let _ = sock.send_to(&response, peer).await;
                if let Some(event) = parse_dns_response(&query, &response, min_ttl, max_ttl) {
                    cb(&event.domain, &event.records);
                }
            }
        });
    }

    Ok(())
}

fn is_loopback_peer(peer: SocketAddr) -> bool {
    match peer.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

async fn forward_dns(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    use tokio::net::UdpSocket;

    let client = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(RouteGuardError::Io)?;
    client
        .send_to(query, upstream)
        .await
        .map_err(RouteGuardError::Io)?;

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.recv_from(&mut buf),
    )
    .await
    .map_err(|_| RouteGuardError::Dns("upstream timeout".into()))?
    .map_err(RouteGuardError::Io)?;

    Ok(buf[..len].to_vec())
}

pub struct DnsParsedEvent {
    pub domain: String,
    pub records: Vec<(IpAddr, u32)>,
}

fn parse_dns_response(
    query: &[u8],
    response: &[u8],
    min_ttl: u32,
    max_ttl: u32,
) -> Option<DnsParsedEvent> {
    if query.len() < 12 || response.len() < 12 {
        return None;
    }

    let qd_count = u16::from_be_bytes([query[4], query[5]]);
    if qd_count == 0 {
        return None;
    }

    let domain = parse_qname(query, 12)?;
    let mut records = Vec::new();

    let mut off = skip_qname(query, 12)?.0;
    off += 4;
    if off + 10 > response.len() {
        return None;
    }

    let ans_count = u16::from_be_bytes([response[6], response[7]]);
    for _ in 0..ans_count {
        if let Some((name_off, _)) = skip_qname(response, off) {
            off = name_off;
        }
        if off + 10 > response.len() {
            break;
        }
        let rtype = u16::from_be_bytes([response[off], response[off + 1]]);
        let ttl = u32::from_be_bytes([
            response[off + 4],
            response[off + 5],
            response[off + 6],
            response[off + 7],
        ]);
        let ttl = ttl.max(min_ttl).min(max_ttl);
        let rdlen = u16::from_be_bytes([response[off + 8], response[off + 9]]) as usize;
        off += 10;
        if off + rdlen > response.len() {
            break;
        }
        match rtype {
            1 if rdlen == 4 => {
                records.push((
                    IpAddr::from([
                        response[off],
                        response[off + 1],
                        response[off + 2],
                        response[off + 3],
                    ]),
                    ttl,
                ));
            }
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&response[off..off + 16]);
                records.push((IpAddr::from(octets), ttl));
            }
            5 if rdlen > 0 => {
                // CNAME — follow one level in additional pass (bounded)
                if let Some(cname) = parse_qname(response, off) {
                    if let Some(cname_records) =
                        parse_cname_chain(response, &cname, min_ttl, max_ttl, 5)
                    {
                        records.extend(cname_records);
                    }
                }
            }
            _ => {}
        }
        off += rdlen;
    }

    if records.is_empty() {
        return None;
    }

    Some(DnsParsedEvent { domain, records })
}

fn parse_cname_chain(
    response: &[u8],
    _target: &str,
    _min_ttl: u32,
    _max_ttl: u32,
    _depth: u32,
) -> Option<Vec<(IpAddr, u32)>> {
    // Full CNAME chase requires re-query upstream; skip in stub pass.
    None
}

fn parse_qname(msg: &[u8], mut off: usize) -> Option<String> {
    let mut labels = Vec::new();
    while off < msg.len() {
        let len = msg[off] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            break;
        }
        off += 1;
        if off + len > msg.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&msg[off..off + len]).into_owned());
        off += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn skip_qname(msg: &[u8], mut off: usize) -> Option<(usize, bool)> {
    let mut compressed = false;
    while off < msg.len() {
        let len = msg[off] as usize;
        if len == 0 {
            off += 1;
            return Some((off, compressed));
        }
        if len & 0xC0 == 0xC0 {
            off += 2;
            compressed = true;
            return Some((off, compressed));
        }
        off += 1 + len;
    }
    None
}

// Legacy event shape for tests / routing crate
impl From<DnsParsedEvent> for DnsResolvedEvent {
    fn from(e: DnsParsedEvent) -> Self {
        let ttl_secs = e.records.first().map(|(_, t)| *t).unwrap_or(300);
        Self {
            domain: e.domain,
            ips: e.records.iter().map(|(ip, _)| *ip).collect(),
            ttl_secs,
        }
    }
}

// Keep unused import for trait surface
#[allow(dead_code)]
struct _PolicyCache(RwLock<()>);
