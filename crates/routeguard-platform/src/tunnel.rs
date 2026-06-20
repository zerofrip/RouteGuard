use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use routeguard_core::config::TunnelConfig;
use routeguard_core::error::{Result, RouteGuardError};
use routeguard_core::tunnel::{
    TunnelBackend, TunnelHandle, TunnelLifecycle, TunnelStats, TunnelStatus,
};

use crate::routes::RouteTableManager;

#[cfg(windows)]
use crate::routes::SessionRoutes;
#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::sync::Mutex;
#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use uuid::Uuid;

#[cfg(windows)]
use crate::wgnt::bindings::WIREGUARD_ADAPTER_STATE;
#[cfg(windows)]
use crate::wgnt::{parse_conf_file, serialize_interface, AdapterHandle, WgntLibrary};
#[cfg(windows)]
use crate::wgnt::{
    query_stats, transition_connect_start, transition_connected, transition_disconnect_start,
    transition_disconnected, transition_error, wait_for_handshake,
};

#[cfg(windows)]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// WireGuardNT tunnel backend using direct wireguard.dll FFI.
pub struct WireGuardNtBackend {
    #[cfg_attr(not(windows), allow(dead_code))]
    dll_path: Option<PathBuf>,
    #[cfg(windows)]
    library: Mutex<Option<Arc<WgntLibrary>>>,
    #[cfg(windows)]
    sessions: Mutex<HashMap<Uuid, TunnelSession>>,
    routes: Arc<RouteTableManager>,
}

#[cfg(windows)]
struct TunnelSession {
    adapter: AdapterHandle,
    lifecycle: TunnelLifecycle,
    created: bool,
    session_routes: SessionRoutes,
}

impl WireGuardNtBackend {
    pub fn new() -> Self {
        Self {
            dll_path: None,
            #[cfg(windows)]
            library: Mutex::new(None),
            #[cfg(windows)]
            sessions: Mutex::new(HashMap::new()),
            routes: Arc::new(RouteTableManager::new()),
        }
    }

    pub fn with_routes(routes: Arc<RouteTableManager>) -> Self {
        Self {
            dll_path: None,
            #[cfg(windows)]
            library: Mutex::new(None),
            #[cfg(windows)]
            sessions: Mutex::new(HashMap::new()),
            routes,
        }
    }

    pub fn with_dll_path(path: impl Into<PathBuf>) -> Self {
        Self {
            dll_path: Some(path.into()),
            ..Self::new()
        }
    }

    pub fn with_routes_and_dll(routes: Arc<RouteTableManager>, dll: impl Into<PathBuf>) -> Self {
        Self {
            dll_path: Some(dll.into()),
            #[cfg(windows)]
            library: Mutex::new(None),
            #[cfg(windows)]
            sessions: Mutex::new(HashMap::new()),
            routes,
        }
    }

    pub fn route_table(&self) -> Arc<RouteTableManager> {
        self.routes.clone()
    }

    #[cfg(windows)]
    fn resolve_dll_path(&self) -> PathBuf {
        self.dll_path.clone().unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("wireguard.dll")))
                .unwrap_or_else(|| PathBuf::from("wireguard.dll"))
        })
    }

    #[cfg(windows)]
    fn library(&self) -> Result<Arc<WgntLibrary>> {
        let mut guard = self.library.lock().unwrap();
        if let Some(lib) = guard.as_ref() {
            return Ok(lib.clone());
        }
        let dll_path = self.resolve_dll_path();
        integrity::verify_or_warn(&dll_path);
        let lib =
            WgntLibrary::load(dll_path).map_err(|e| RouteGuardError::Tunnel(e.to_string()))?;
        *guard = Some(lib.clone());
        Ok(lib)
    }

    #[cfg(windows)]
    fn install_routes(
        &self,
        session: &mut TunnelSession,
        if_index: u32,
        conf: &crate::wgnt::ParsedConf,
    ) -> Result<()> {
        if let Some(ep) = conf.peers.first().and_then(|p| p.endpoint) {
            session
                .session_routes
                .add_endpoint_bypass(&self.routes, ep, if_index)?;
        }

        for peer in &conf.peers {
            for cidr in &peer.allowed_ips {
                if cidr.prefix_len() == 0 {
                    session
                        .session_routes
                        .add_default_route(&self.routes, *cidr, if_index)?;
                } else {
                    session
                        .session_routes
                        .add_bypass(&self.routes, *cidr, if_index)?;
                }
            }
        }

        Ok(())
    }
}

impl Default for WireGuardNtBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunnelBackend for WireGuardNtBackend {
    fn name(&self) -> &str {
        "wireguard-nt-native"
    }

    async fn up(&self, config: &TunnelConfig) -> Result<TunnelHandle> {
        #[cfg(windows)]
        {
            return self.up_impl(config).await;
        }
        #[cfg(not(windows))]
        {
            let _ = config;
            Err(RouteGuardError::UnsupportedPlatform)
        }
    }

    async fn down(&self, handle: &TunnelHandle) -> Result<()> {
        #[cfg(windows)]
        {
            return self.down_impl(handle).await;
        }
        #[cfg(not(windows))]
        {
            let _ = handle;
            Err(RouteGuardError::UnsupportedPlatform)
        }
    }

    fn status(&self, handle: &TunnelHandle) -> TunnelStatus {
        self.lifecycle(handle)
    }

    fn lifecycle(&self, handle: &TunnelHandle) -> TunnelLifecycle {
        #[cfg(windows)]
        {
            return self
                .sessions
                .lock()
                .unwrap()
                .get(&handle.id)
                .map(|s| s.lifecycle)
                .unwrap_or(TunnelLifecycle::Disconnected);
        }
        #[cfg(not(windows))]
        {
            let _ = handle;
            TunnelLifecycle::Disconnected
        }
    }

    fn stats(&self, handle: &TunnelHandle) -> Result<TunnelStats> {
        #[cfg(windows)]
        {
            let sessions = self.sessions.lock().unwrap();
            let session = sessions
                .get(&handle.id)
                .ok_or_else(|| RouteGuardError::Tunnel("session not found".into()))?;
            let iface_stats = query_stats(&session.adapter)
                .map_err(|e| RouteGuardError::Tunnel(e.to_string()))?;
            let (rx, tx) = iface_stats.totals();
            let last_handshake_secs_ago = iface_stats
                .peers
                .iter()
                .filter_map(|p| p.last_handshake)
                .flat_map(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .saturating_sub(d)
                        .as_secs()
                })
                .min();
            return Ok(TunnelStats {
                rx_bytes: rx,
                tx_bytes: tx,
                last_handshake_secs_ago,
                peer_count: iface_stats.peers.len(),
            });
        }
        #[cfg(not(windows))]
        {
            let _ = handle;
            Err(RouteGuardError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
impl WireGuardNtBackend {
    async fn up_impl(&self, config: &TunnelConfig) -> Result<TunnelHandle> {
        let library = self.library()?;
        let parsed = parse_conf_file(&config.config_path)
            .map_err(|e| RouteGuardError::Tunnel(e.to_string()))?;
        let wire_config =
            serialize_interface(&parsed).map_err(|e| RouteGuardError::Tunnel(e.to_string()))?;

        let (adapter, created) = AdapterHandle::open_or_create(library.clone(), &config.name)
            .map_err(|e| RouteGuardError::Tunnel(e.to_string()))?;

        adapter
            .set_configuration(&wire_config)
            .map_err(|e| RouteGuardError::Tunnel(e.to_string()))?;

        adapter
            .set_adapter_state(WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_UP)
            .map_err(|e| RouteGuardError::Tunnel(e.to_string()))?;

        let luid = adapter
            .luid()
            .map_err(|e| RouteGuardError::Tunnel(e.to_string()))?;
        let if_index = luid_to_if_index(luid);
        let id = Uuid::new_v4();

        let mut session = TunnelSession {
            adapter,
            lifecycle: transition_connect_start(),
            created,
            session_routes: SessionRoutes::new(),
        };

        if let Err(e) = self.install_routes(&mut session, if_index, &parsed) {
            session.lifecycle = transition_error();
            return Err(e);
        }

        match wait_for_handshake(&session.adapter, HANDSHAKE_TIMEOUT).await {
            Ok(_) => session.lifecycle = transition_connected(),
            Err(e) => {
                session.lifecycle = transition_error();
                let _ = session
                    .adapter
                    .set_adapter_state(WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_DOWN);
                return Err(RouteGuardError::Tunnel(e.to_string()));
            }
        }

        self.sessions.lock().unwrap().insert(id, session);

        Ok(TunnelHandle {
            id,
            name: config.name.clone(),
            if_index,
            if_luid: luid,
            backend: routeguard_core::backend::BackendKind::WireGuardNt,
        })
    }

    async fn down_impl(&self, handle: &TunnelHandle) -> Result<()> {
        let mut session = self
            .sessions
            .lock()
            .unwrap()
            .remove(&handle.id)
            .ok_or_else(|| RouteGuardError::Tunnel("session not found".into()))?;

        session.lifecycle = transition_disconnect_start();

        let _ = session
            .adapter
            .set_adapter_state(WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_DOWN);

        session
            .session_routes
            .clear(&self.routes)
            .map_err(|e| RouteGuardError::Tunnel(e.to_string()))?;

        session.lifecycle = transition_disconnected();
        Ok(())
    }
}

#[cfg(windows)]
fn luid_to_if_index(luid: u64) -> u32 {
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let mut if_index = 0u32;
    let net_luid = NET_LUID_LH { Value: luid };
    unsafe {
        if ConvertInterfaceLuidToIndex(&net_luid, &mut if_index) != 0 {
            return 0;
        }
    }
    if_index
}

#[cfg(windows)]
pub fn teardown_orphan_adapter(library: &WgntLibrary, name: &str) {
    if let Ok(handle) = library.open_adapter(name) {
        library.close_adapter(handle);
    }
}
