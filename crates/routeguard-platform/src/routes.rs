use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ipnet::IpNet;
use routeguard_core::config::RouteTarget;
use routeguard_core::error::Result;
use routeguard_core::policy::PolicySnapshot;

/// Opaque route table entry handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteHandle(pub u64);

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn alloc_handle() -> RouteHandle {
    RouteHandle(NEXT_HANDLE.fetch_add(1, Ordering::Relaxed))
}

#[derive(Debug, Clone)]
struct DomainRouteHandle {
    #[allow(dead_code)]
    ip: IpAddr,
    route_handle: RouteHandle,
    expires_at: u64,
    target: RouteTarget,
}

/// Routes and WFP filter IDs installed for a single tunnel session.
#[derive(Debug, Default)]
pub struct SessionRoutes {
    wg_handles: Vec<RouteHandle>,
    split_handles: Vec<RouteHandle>,
    domain_routes: HashMap<IpAddr, DomainRouteHandle>,
    pub wfp_filter_ids: Vec<u64>,
}

impl SessionRoutes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_default_route(
        &mut self,
        table: &RouteTableManager,
        cidr: IpNet,
        if_index: u32,
    ) -> Result<()> {
        let h = table.set_default_via_tunnel(if_index, cidr)?;
        self.wg_handles.push(h);
        Ok(())
    }

    pub fn add_bypass(
        &mut self,
        table: &RouteTableManager,
        cidr: IpNet,
        if_index: u32,
    ) -> Result<()> {
        let h = table.add_bypass_route(cidr, if_index)?;
        self.wg_handles.push(h);
        Ok(())
    }

    pub fn add_endpoint_bypass(
        &mut self,
        table: &RouteTableManager,
        endpoint: SocketAddr,
        tunnel_if_index: u32,
    ) -> Result<()> {
        let cidr: IpNet = IpNet::from(endpoint.ip());
        let h = table.add_host_route_outside_tunnel(cidr, tunnel_if_index)?;
        self.wg_handles.push(h);
        Ok(())
    }

    pub fn install_split_routes(
        &mut self,
        table: &RouteTableManager,
        policy: &PolicySnapshot,
    ) -> Result<()> {
        self.clear_split(table)?;

        let tunnel_if = match policy.tunnel_if_index {
            Some(i) => i,
            None => return Ok(()),
        };
        let physical_if = match policy.physical_if_index {
            Some(i) => i,
            None => return Ok(()),
        };

        let v4: IpNet = "0.0.0.0/0".parse().expect("valid v4");
        self.split_handles
            .push(table.add_route(v4, physical_if, 1)?);
        self.split_handles
            .push(table.add_route(v4, tunnel_if, 100)?);

        if let Ok(v6) = "::/0".parse::<IpNet>() {
            self.split_handles
                .push(table.add_route(v6, physical_if, 1)?);
            self.split_handles
                .push(table.add_route(v6, tunnel_if, 100)?);
        }

        for cidr in &policy.bypass_cidrs {
            let net: IpNet = cidr.parse().map_err(|e| {
                routeguard_core::error::RouteGuardError::Routing(format!("bad cidr: {e}"))
            })?;
            self.split_handles
                .push(table.add_route(net, physical_if, 1)?);
        }

        for cidr in &policy.dynamic_tunnel_hosts {
            let net: IpNet = cidr.parse().map_err(|e| {
                routeguard_core::error::RouteGuardError::Routing(format!("bad dynamic tunnel: {e}"))
            })?;
            self.split_handles
                .push(table.add_route(net, tunnel_if, 100)?);
        }

        Ok(())
    }

    /// Install or refresh a per-IP host route for domain routing.
    pub fn install_domain_route(
        &mut self,
        table: &RouteTableManager,
        ip: IpAddr,
        target: RouteTarget,
        tunnel_if: u32,
        physical_if: u32,
        expires_at: u64,
    ) -> Result<()> {
        if let Some(existing) = self.domain_routes.get(&ip) {
            if existing.expires_at >= expires_at && existing.target == target {
                return Ok(());
            }
            self.remove_domain_route(table, ip)?;
        }

        let cidr: IpNet = IpNet::from(ip);
        let if_index = match target {
            RouteTarget::Bypass => physical_if,
            RouteTarget::Tunnel => tunnel_if,
            RouteTarget::Block => return Ok(()),
        };
        let metric = if target == RouteTarget::Tunnel {
            100
        } else {
            1
        };
        let handle = table.add_route(cidr, if_index, metric)?;
        self.domain_routes.insert(
            ip,
            DomainRouteHandle {
                ip,
                route_handle: handle,
                expires_at,
                target,
            },
        );
        Ok(())
    }

    pub fn remove_domain_route(&mut self, table: &RouteTableManager, ip: IpAddr) -> Result<()> {
        if let Some(entry) = self.domain_routes.remove(&ip) {
            table.remove_route(entry.route_handle)?;
        }
        Ok(())
    }

    pub fn purge_expired_domain_routes(
        &mut self,
        table: &RouteTableManager,
    ) -> Result<Vec<IpAddr>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expired: Vec<IpAddr> = self
            .domain_routes
            .iter()
            .filter(|(_, h)| h.expires_at <= now)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in &expired {
            self.remove_domain_route(table, *ip)?;
        }
        Ok(expired)
    }

    pub fn clear_domain_routes(&mut self, table: &RouteTableManager) -> Result<()> {
        let ips: Vec<_> = self.domain_routes.keys().copied().collect();
        for ip in ips {
            self.remove_domain_route(table, ip)?;
        }
        Ok(())
    }

    pub fn domain_route_count(&self) -> usize {
        self.domain_routes.len()
    }

    pub fn clear_split(&mut self, table: &RouteTableManager) -> Result<()> {
        for h in self.split_handles.drain(..) {
            table.remove_route(h)?;
        }
        Ok(())
    }

    pub fn clear(&mut self, table: &RouteTableManager) -> Result<()> {
        self.clear_domain_routes(table)?;
        self.clear_split(table)?;
        for h in self.wg_handles.drain(..) {
            table.remove_route(h)?;
        }
        self.wfp_filter_ids.clear();
        Ok(())
    }
}

#[async_trait]
pub trait RouteTable: Send + Sync {
    fn add_route(&self, cidr: IpNet, if_index: u32, metric: u32) -> Result<RouteHandle>;
    fn set_default_via_tunnel(&self, if_index: u32, cidr: IpNet) -> Result<RouteHandle>;
    fn add_bypass_route(&self, cidr: IpNet, if_index: u32) -> Result<RouteHandle>;
    fn add_host_route_outside_tunnel(
        &self,
        cidr: IpNet,
        tunnel_if_index: u32,
    ) -> Result<RouteHandle>;
    fn remove_route(&self, handle: RouteHandle) -> Result<()>;
    fn clear(&self) -> Result<()>;
}

pub struct RouteTableManager {
    routes: Mutex<HashMap<RouteHandle, IpNet>>,
}

impl RouteTableManager {
    pub fn new() -> Self {
        Self {
            routes: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for RouteTableManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RouteTable for RouteTableManager {
    fn add_route(&self, cidr: IpNet, if_index: u32, metric: u32) -> Result<RouteHandle> {
        let handle = alloc_handle();
        #[cfg(windows)]
        {
            windows_routes::add_route(cidr, if_index, metric)?;
        }
        #[cfg(not(windows))]
        {
            let _ = (if_index, metric);
            tracing::debug!("stub add_route {cidr}");
        }
        self.routes.lock().unwrap().insert(handle, cidr);
        Ok(handle)
    }

    fn set_default_via_tunnel(&self, if_index: u32, cidr: IpNet) -> Result<RouteHandle> {
        self.add_route(cidr, if_index, 100)
    }

    fn add_bypass_route(&self, cidr: IpNet, if_index: u32) -> Result<RouteHandle> {
        self.add_route(cidr, if_index, 5)
    }

    fn add_host_route_outside_tunnel(
        &self,
        cidr: IpNet,
        tunnel_if_index: u32,
    ) -> Result<RouteHandle> {
        self.add_route(cidr, tunnel_if_index, 0)
    }

    fn remove_route(&self, handle: RouteHandle) -> Result<()> {
        if let Some(cidr) = self.routes.lock().unwrap().remove(&handle) {
            #[cfg(windows)]
            {
                windows_routes::delete_route(cidr)?;
            }
            #[cfg(not(windows))]
            let _ = cidr;
        }
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        let handles: Vec<_> = self.routes.lock().unwrap().keys().copied().collect();
        for h in handles {
            let _ = self.remove_route(h);
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows_routes {
    use ipnet::IpNet;
    use routeguard_core::error::{Result, RouteGuardError};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    pub fn add_route(cidr: IpNet, if_index: u32, metric: u32) -> Result<()> {
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceIndex = if_index;
        row.Metric = metric;
        row.Protocol = windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPPROTO_NETMGMT as i32;

        match cidr {
            IpNet::V4(net) => {
                row.DestinationPrefix.Prefix.s_addr = u32::from_be_bytes(net.addr().octets());
                row.DestinationPrefix.PrefixLength = net.prefix_len();
                row.NextHop.s_addr = 0;
            }
            IpNet::V6(net) => {
                row.DestinationPrefix.PrefixLength = net.prefix_len();
                row.DestinationPrefix.Prefix.Ipv6.sin6_addr = net.addr().octets();
            }
        }

        let family = match cidr {
            IpNet::V4(_) => AF_INET,
            IpNet::V6(_) => AF_INET6,
        };

        let status = unsafe { CreateIpForwardEntry2(&row, family as u16) };
        if status != 0 {
            return Err(RouteGuardError::Platform(format!(
                "CreateIpForwardEntry2 failed: {status}"
            )));
        }
        Ok(())
    }

    pub fn delete_route(cidr: IpNet) -> Result<()> {
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };

        match cidr {
            IpNet::V4(net) => {
                row.DestinationPrefix.Prefix.s_addr = u32::from_be_bytes(net.addr().octets());
                row.DestinationPrefix.PrefixLength = net.prefix_len();
            }
            IpNet::V6(net) => {
                row.DestinationPrefix.PrefixLength = net.prefix_len();
                row.DestinationPrefix.Prefix.Ipv6.sin6_addr = net.addr().octets();
            }
        }

        let family = match cidr {
            IpNet::V4(_) => AF_INET,
            IpNet::V6(_) => AF_INET6,
        };

        let status = unsafe { DeleteIpForwardEntry2(&row, family as u16) };
        if status != 0 && status != 1168 {
            return Err(RouteGuardError::Platform(format!(
                "DeleteIpForwardEntry2 failed: {status}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_routes_tracks_split_handles() {
        let table = RouteTableManager::new();
        let mut session = SessionRoutes::new();
        let cidr: IpNet = "10.0.0.0/8".parse().unwrap();
        let h = table.add_route(cidr, 1, 5).unwrap();
        session.split_handles.push(h);
        assert_eq!(session.split_handles.len(), 1);
        session.clear_split(&table).unwrap();
        assert!(session.split_handles.is_empty());
    }
}
