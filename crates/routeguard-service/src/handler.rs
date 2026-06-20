use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use routeguard_core::backend::BackendKind;
use routeguard_core::config::{AppConfig, DomainDnsConfig, RuleMode};
use routeguard_core::config::{AppRule, DomainRule, IpRule, RouteTarget, RoutingMode};
use routeguard_core::error::{Result, RouteGuardError};
use routeguard_core::events::{EventStore, TunnelEvent};
use routeguard_core::ipc::methods;
use routeguard_core::ipc::{
    AddAppRuleParams, ConnectParams, EventsPollParams, ImportRulesParams, IpcHandler, IpcRequest,
    IpcResponse, RemoveAppRuleParams, RoutingListResult, RoutingTestParams, RoutingTestResult,
    ServiceCapabilitiesResult, ServiceFeatures, ServiceLimits, ServicePingResult,
    TransportCapabilityEntry, TunnelContextParams, TunnelStatusResult,
};
use routeguard_core::observability::{
    list_metrics, DiagnosticsExportParams, MetricsListResult, ObservabilityFeatures,
    ObservabilityHistoryParams, ObservabilityHistoryResult, ObservabilitySnapshotParams,
};
use routeguard_core::orchestrator::TunnelOrchestrator;
use routeguard_core::policy::PolicySnapshot;
use routeguard_core::profile::{ProfileExportParams, ProfileImportParams, ProfileValidateParams};
use routeguard_platform::{
    discover_physical_if_index, AwgBackend, DnsInterceptor, DnsProxy, DnsProxyConfig,
    DnsResponseCallback, RouteTableManager, SessionRoutes, WireGuardNtBackend,
};
use routeguard_routing::policy::PolicyCompiler;
use routeguard_routing::{
    add_app_rule, default_priority_for_mode, remove_app_rule, AddAppRuleRequest,
    DomainRouteStoreConfig, FlowContext, Protocol, RoutingEngine,
};

use crate::backend_selector::TunnelBackendSelector;
use crate::connect_session::{ActiveConnectSession, ConnectSessionStore};
use crate::domain_routing::DomainRoutingManager;
use crate::event_bridge;
use crate::observability::{
    collect_snapshot, export_diagnostics, ObservabilityRuntime, SharedObservability,
};
use crate::profile_store;
use crate::transport_selector::{TransportChoice, TransportSelector};
use routeguard_core::transport::{parse_peer_endpoint, transport_summary, TransportKind};
use serde_json::{json, Value};
use std::time::Instant;
use tokio::sync::RwLock;

#[cfg(windows)]
use routeguard_wfp::{probe_callout_driver, DnsCalloutManager, NetworkLockPolicy, WfpSession};
#[cfg(windows)]
use std::net::SocketAddr;
#[cfg(windows)]
use tokio::sync::Mutex as AsyncMutex;

pub struct ServiceContext {
    pub orchestrator: Arc<TunnelOrchestrator>,
    pub selector: Arc<TunnelBackendSelector>,
    pub transport_selector: Arc<TransportSelector>,
    pub active_session: Arc<ConnectSessionStore>,
    pub routes: Arc<RouteTableManager>,
    pub session_routes: Arc<Mutex<SessionRoutes>>,
    pub routing: Arc<RwLock<RoutingEngine>>,
    pub dns: Arc<DnsProxy>,
    pub domain_mgr: Arc<DomainRoutingManager>,
    pub cached_policy: Arc<std::sync::RwLock<Option<PolicySnapshot>>>,
    pub event_store: Arc<EventStore>,
    pub external_tunnel: Arc<RwLock<Option<TunnelContextParams>>>,
    pub started_at: Instant,
    pub observability: SharedObservability,
    #[cfg(windows)]
    pub wfp: Arc<AsyncMutex<Option<WfpSession>>>,
    #[cfg(windows)]
    pub dns_callout: Arc<AsyncMutex<DnsCalloutManager>>,
}

fn dns_config_from(cfg: &DomainDnsConfig) -> (DnsProxyConfig, DomainRouteStoreConfig) {
    let listen: std::net::SocketAddr = cfg
        .listen
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:5353".parse().unwrap());
    let listen_v6 = cfg.listen_v6.parse().ok();
    let upstream: Vec<std::net::SocketAddr> =
        cfg.upstream.iter().filter_map(|s| s.parse().ok()).collect();
    (
        DnsProxyConfig {
            listen,
            listen_v6,
            upstream,
            min_ttl_secs: cfg.min_ttl_secs,
            max_ttl_secs: cfg.max_ttl_secs,
        },
        DomainRouteStoreConfig {
            max_resolved_ips: cfg.max_resolved_ips,
            max_domains: cfg.max_domains,
            min_ttl_secs: cfg.min_ttl_secs,
            max_ttl_secs: cfg.max_ttl_secs,
        },
    )
}

impl ServiceContext {
    pub async fn new(config_path: PathBuf, config: AppConfig) -> Result<Self> {
        let orchestrator = Arc::new(TunnelOrchestrator::new(config_path, config.clone()));
        let routing = RoutingEngine::from_config(&config).map_err(RouteGuardError::Routing)?;
        let routes = Arc::new(RouteTableManager::new());
        let wgnt = WireGuardNtBackend::with_routes(routes.clone());
        let awg = AwgBackend::with_routes(routes.clone());
        let selector = TunnelBackendSelector::new(wgnt, awg);
        let transport_selector = Arc::new(TransportSelector::new());
        let active_session = Arc::new(ConnectSessionStore::new());
        let observability: SharedObservability = Arc::new(ObservabilityRuntime::new());
        let routing_arc = Arc::new(RwLock::new(routing));
        let event_store = Arc::new(EventStore::new(512));
        event_bridge::spawn_event_bridge(orchestrator.events(), event_store.clone());
        let cached_policy = Arc::new(std::sync::RwLock::new(None));

        let (dns_cfg, store_cfg) = dns_config_from(&config.routing.domain_dns);
        let domain_mgr = Arc::new(DomainRoutingManager::new(
            event_store.clone(),
            routing_arc.clone(),
            store_cfg,
        ));
        domain_mgr.set_explicit_proxy(config.routing.domain_dns.explicit_proxy);
        domain_mgr.rebuild_rules(&config.routing.domain_rules);

        let session_routes = Arc::new(Mutex::new(SessionRoutes::new()));
        let routes_for_dns = routes.clone();
        let mgr_for_dns = domain_mgr.clone();
        let sr_for_dns = session_routes.clone();
        let policy_for_dns = cached_policy.clone();

        let on_dns: DnsResponseCallback = Arc::new(move |domain, records| {
            let policy = policy_for_dns
                .read()
                .ok()
                .and_then(|g| g.clone())
                .unwrap_or_default();
            mgr_for_dns.on_dns_response(domain, records, &sr_for_dns, &routes_for_dns, &policy);
        });

        let dns = Arc::new(DnsProxy::new(dns_cfg, on_dns));
        if config.routing.domain_dns.enabled {
            let _ = dns.start().await;
        }

        #[cfg(windows)]
        let wfp = {
            let session = WfpSession::open()?;
            Arc::new(AsyncMutex::new(Some(session)))
        };

        #[cfg(windows)]
        let dns_callout = Arc::new(AsyncMutex::new(DnsCalloutManager::new()));

        let ctx_self_prep = (
            domain_mgr.clone(),
            session_routes.clone(),
            routes.clone(),
            cached_policy.clone(),
        );

        // Purge timer every 15s
        {
            let (dm, sr, rt, cp) = ctx_self_prep;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
                loop {
                    interval.tick().await;
                    dm.purge_expired(&sr, &rt);
                    let _ = dm.persist();
                }
            });
            let _ = cp; // policy cache updated elsewhere
        }

        // Periodic persist every 60s
        {
            let dm = domain_mgr.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let _ = dm.persist();
                }
            });
        }

        Ok(Self {
            orchestrator,
            selector: Arc::new(selector),
            transport_selector,
            active_session,
            routes,
            session_routes: session_routes.clone(),
            routing: routing_arc,
            dns,
            domain_mgr,
            cached_policy,
            event_store,
            external_tunnel: Arc::new(RwLock::new(None)),
            started_at: Instant::now(),
            observability,
            #[cfg(windows)]
            wfp,
            #[cfg(windows)]
            dns_callout,
        })
    }

    pub(crate) async fn build_policy(&self) -> Result<PolicySnapshot> {
        let cfg = self.orchestrator.get_config().await;
        let handle = self.orchestrator.active_handle().await;
        let external = self.external_tunnel.read().await.clone();
        let routing = self.routing.read().await;

        let (tunnel_if_index, tunnel_if_luid, endpoint_from_ctx) = if let Some(h) = &handle {
            (Some(h.if_index), Some(h.if_luid), None)
        } else if let Some(ext) = external.as_ref().filter(|c| c.connected) {
            (ext.if_index, None, ext.endpoint_ip.clone())
        } else {
            (None, None, None)
        };

        let physical_if = tunnel_if_index.and_then(|idx| {
            discover_physical_if_index(idx)
                .ok()
                .or(Some(0))
                .filter(|&i| i != 0)
        });

        let mut policy = PolicyCompiler::compile_with_domain_store(
            &cfg,
            &routing,
            tunnel_if_index,
            tunnel_if_luid,
            physical_if,
            Some(&self.domain_mgr.snapshot_store()),
        );

        if let Some(ep) = endpoint_from_ctx {
            policy.endpoint = Some(ep);
        } else if let Some(h) = &handle {
            if let Ok(conf) = tokio::fs::read_to_string(
                cfg.tunnel
                    .as_ref()
                    .map(|t| &t.config_path)
                    .ok_or_else(|| RouteGuardError::Config("no tunnel".into()))?,
            )
            .await
            {
                policy.endpoint = routeguard_wfp::filters::parse_endpoint_from_config(&conf)
                    .map(|a| a.to_string());
            }
            policy.tunnel_if_index = Some(h.if_index);
            policy.tunnel_if_luid = Some(h.if_luid);
            policy.physical_if_index = physical_if;
        } else if let Some(ext) = external.as_ref().filter(|c| c.connected) {
            policy.tunnel_if_index = ext.if_index;
            policy.physical_if_index = physical_if;
        }

        for upstream in &cfg.routing.domain_dns.upstream {
            if !policy.dns_servers.contains(upstream) {
                policy.dns_servers.push(upstream.clone());
            }
        }

        if let Some(active) = self.active_session.active() {
            let endpoints = self
                .transport_selector
                .policy_endpoints(active.transport_choice, &active.transport_session);
            policy.endpoint = Some(endpoints.wireguard_endpoint.to_string());
            policy.transport_permits = endpoints.extra_permits;
            for ip in endpoints.bypass_ips {
                let host = format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 });
                if !policy.bypass_cidrs.contains(&host) {
                    policy.bypass_cidrs.push(host);
                }
            }
        }

        Ok(policy)
    }

    async fn cache_policy(&self, policy: &PolicySnapshot) {
        if let Ok(mut guard) = self.cached_policy.write() {
            *guard = Some(policy.clone());
        }
    }

    pub(crate) async fn has_active_tunnel(&self) -> bool {
        if self.orchestrator.active_handle().await.is_some() {
            return true;
        }
        self.external_tunnel
            .read()
            .await
            .as_ref()
            .map(|c| c.connected)
            .unwrap_or(false)
    }

    async fn apply_split_policy(&self) -> Result<()> {
        let policy = self.build_policy().await?;
        self.cache_policy(&policy).await;

        if self.has_active_tunnel().await {
            self.session_routes
                .lock()
                .unwrap()
                .install_split_routes(&self.routes, &policy)?;
            self.domain_mgr.reinstall_routes_from_cache(
                &self.session_routes,
                &self.routes,
                &policy,
            );
        }

        self.apply_domain_dns_wfp(&policy).await?;

        #[cfg(windows)]
        self.apply_split_wfp(policy).await?;

        Ok(())
    }

    async fn apply_domain_dns_wfp(&self, policy: &PolicySnapshot) -> Result<()> {
        let cfg = self.orchestrator.get_config().await;
        let dns_cfg = &cfg.routing.domain_dns;
        let has_rules = !cfg.routing.domain_rules.is_empty();

        self.domain_mgr.set_explicit_proxy(dns_cfg.explicit_proxy);

        let want_redirect =
            dns_cfg.enabled && has_rules && (dns_cfg.redirect_port_53 || dns_cfg.kernel_redirect);

        #[cfg(windows)]
        if want_redirect {
            let port = dns_cfg
                .listen
                .split(':')
                .nth(1)
                .and_then(|p| p.parse().ok())
                .unwrap_or(5353);
            let excluded = vec![std::process::id()];
            let mut mgr = self.dns_callout.lock().await;
            let mut wfp = self.wfp.lock().await;
            if let Some(session) = wfp.as_mut() {
                let inner = session.inner_mut();
                match mgr.install(inner, port, &excluded, dns_cfg.kernel_redirect) {
                    Ok(active) => {
                        self.domain_mgr.set_dns_redirect_active(active);
                        let state = routeguard_wfp::persistent::DnsRedirectState {
                            wfp_filter_ids: mgr.filter_ids().to_vec(),
                            kernel_active: mgr.kernel_active(),
                            proxy_port: port,
                            applied_at: Some(chrono_lite_now()),
                        };
                        let _ = routeguard_wfp::persistent::save_dns_redirect_state(&state);
                    }
                    Err(e) => {
                        tracing::warn!("DNS callout install failed: {e}");
                        self.domain_mgr.set_dns_redirect_active(false);
                        if dns_cfg.kernel_redirect {
                            return Err(e);
                        }
                    }
                }
            }
        } else {
            self.domain_mgr.set_dns_redirect_active(false);
            #[cfg(windows)]
            {
                let mut mgr = self.dns_callout.lock().await;
                let mut wfp = self.wfp.lock().await;
                if let Some(session) = wfp.as_mut() {
                    let _ = mgr.remove(session.inner_mut());
                }
                let _ = routeguard_wfp::persistent::save_dns_redirect_state(
                    &routeguard_wfp::persistent::DnsRedirectState::default(),
                );
            }
        }

        // Upstream DNS merged into policy.dns_servers in build_policy for NL permits
        let _ = policy;
        Ok(())
    }

    #[cfg(windows)]
    async fn apply_split_wfp(&self, mut policy: PolicySnapshot) -> Result<()> {
        let cfg = self.orchestrator.get_config().await;
        let previous_wfp = self.session_routes.lock().unwrap().wfp_filter_ids.clone();

        let mut wfp = self.wfp.lock().await;
        if let Some(session) = wfp.as_mut() {
            let new_ids = session.apply_split_policy(&policy, &previous_wfp)?;
            policy.wfp_filter_ids = new_ids;
            self.session_routes.lock().unwrap().wfp_filter_ids = policy.wfp_filter_ids.clone();

            if cfg.network_lock.enabled {
                let ep = policy
                    .endpoint
                    .as_deref()
                    .and_then(|s| s.parse::<SocketAddr>().ok());
                let dns: Vec<SocketAddr> = policy
                    .dns_servers
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                session.enable_network_lock(&NetworkLockPolicy {
                    enabled: true,
                    allow_lan: policy.allow_lan,
                    dns_servers: dns,
                    tunnel_if_index: policy.tunnel_if_index,
                    endpoint: ep,
                    transport_permits: policy.transport_permits.clone(),
                })?;
            }
        }

        let app_state = routeguard_wfp::persistent::AppRulesState {
            rules: cfg.routing.app_rules.clone(),
            wfp_filter_ids: policy.wfp_filter_ids.clone(),
            tunnel_if_index: policy.tunnel_if_index,
            physical_if_index: policy.physical_if_index,
            applied_at: Some(chrono_lite_now()),
        };
        routeguard_wfp::persistent::save_app_rules_state(&app_state)?;
        routeguard_wfp::persistent::save_session_snapshot(&policy)?;

        Ok(())
    }

    pub(crate) async fn apply_full_policy(&self) -> Result<()> {
        self.apply_split_policy().await
    }

    async fn reload_routing_from_disk(&self) -> Result<()> {
        let cfg = self.orchestrator.load_config().await?;
        let engine = RoutingEngine::from_config(&cfg).map_err(RouteGuardError::Routing)?;
        *self.routing.write().await = engine;
        self.apply_split_policy().await
    }
}

#[cfg(windows)]
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

fn parse_rule_mode(s: &str) -> Result<RuleMode> {
    match s.to_ascii_lowercase().as_str() {
        "exclude" => Ok(RuleMode::Exclude),
        "include" => Ok(RuleMode::Include),
        _ => Err(RouteGuardError::Routing(format!("invalid mode: {s}"))),
    }
}

fn parse_route_target(s: &str) -> Result<RouteTarget> {
    match s.to_ascii_lowercase().as_str() {
        "tunnel" | "vpn" => Ok(RouteTarget::Tunnel),
        "bypass" | "direct" => Ok(RouteTarget::Bypass),
        "block" => Ok(RouteTarget::Block),
        _ => Err(RouteGuardError::Routing(format!("invalid target: {s}"))),
    }
}

#[async_trait]
impl IpcHandler for ServiceContext {
    async fn handle(&self, req: IpcRequest) -> IpcResponse {
        match req.method.as_str() {
            methods::TUNNEL_CONNECT => self.handle_connect(req.id, req.params).await,
            methods::TUNNEL_DISCONNECT => self.handle_disconnect(req.id).await,
            methods::TUNNEL_STATUS => self.handle_status(req.id).await,
            methods::ROUTING_RELOAD => self.handle_routing_reload(req.id).await,
            methods::ROUTING_GET => self.handle_routing_get(req.id).await,
            methods::ROUTING_ADD_APP => self.handle_routing_add_app(req.id, req.params).await,
            methods::ROUTING_REMOVE_APP => self.handle_routing_remove_app(req.id, req.params).await,
            methods::ROUTING_TEST => self.handle_routing_test(req.id, req.params).await,
            methods::NETWORK_LOCK_ENABLE => self.handle_nl_enable(req.id).await,
            methods::NETWORK_LOCK_DISABLE => self.handle_nl_disable(req.id).await,
            methods::NETWORK_LOCK_STATUS => self.handle_nl_status(req.id).await,
            methods::CONFIG_GET => self.handle_config_get(req.id).await,
            methods::CONFIG_SET => self.handle_config_set(req.id, req.params).await,
            methods::LOGS_TAIL => self.handle_logs_tail(req.id, req.params).await,
            methods::SERVICE_PING => self.handle_service_ping(req.id).await,
            methods::SERVICE_CAPABILITIES => self.handle_service_capabilities(req.id).await,
            methods::ROUTING_IMPORT_RULES => {
                self.handle_routing_import_rules(req.id, req.params).await
            }
            methods::ROUTING_SET_TUNNEL_CONTEXT => {
                self.handle_routing_set_tunnel_context(req.id, req.params)
                    .await
            }
            methods::EVENTS_POLL => self.handle_events_poll(req.id, req.params).await,
            methods::DOMAIN_STATUS => self.handle_domain_status(req.id).await,
            methods::TUNNEL_PROFILE_LIST => self.handle_profile_list(req.id).await,
            methods::TUNNEL_PROFILE_GET => self.handle_profile_get(req.id, req.params).await,
            methods::TUNNEL_PROFILE_IMPORT => self.handle_profile_import(req.id, req.params).await,
            methods::TUNNEL_PROFILE_EXPORT => self.handle_profile_export(req.id, req.params).await,
            methods::TUNNEL_PROFILE_VALIDATE => {
                self.handle_profile_validate(req.id, req.params).await
            }
            methods::TUNNEL_PROFILE_DELETE => self.handle_profile_delete(req.id, req.params).await,
            methods::OBSERVABILITY_SNAPSHOT => {
                self.handle_observability_snapshot(req.id, req.params).await
            }
            methods::OBSERVABILITY_HISTORY => {
                self.handle_observability_history(req.id, req.params).await
            }
            methods::SERVICE_HEALTH => self.handle_service_health(req.id).await,
            methods::METRICS_LIST => self.handle_metrics_list(req.id).await,
            methods::DIAGNOSTICS_EXPORT => self.handle_diagnostics_export(req.id, req.params).await,
            _ => IpcResponse::err(req.id, -32601, format!("unknown method {}", req.method)),
        }
    }
}

impl ServiceContext {
    async fn handle_connect(&self, id: u64, params: Value) -> IpcResponse {
        let p: ConnectParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };

        let cfg = self.orchestrator.get_config().await;
        let mut tunnel_cfg = match cfg.tunnel.clone() {
            Some(mut t) => {
                if let Some(n) = p.name {
                    t.name = n;
                }
                t
            }
            None => return IpcResponse::err(id, -32602, "no tunnel configured".to_string()),
        };

        let mut profile_transport = None;
        if let Some(profile_name) = &p.profile_name {
            if let Ok(Some(profile)) = profile_store::get_profile(profile_name) {
                tunnel_cfg.name = profile.name.clone();
                tunnel_cfg.config_path = profile.config_path.clone();
                tunnel_cfg.backend = profile.backend;
                if let Some(t) = profile.transport.clone() {
                    tunnel_cfg.transport = t.clone();
                    profile_transport = Some(t);
                }
            }
        }

        if let Some(path) = p.config_path {
            tunnel_cfg.config_path = path;
        }

        {
            let mut cfg = cfg;
            cfg.tunnel = Some(tunnel_cfg.clone());
            let _ = self.orchestrator.set_config(cfg).await;
        }

        let conf_text = match tokio::fs::read_to_string(&tunnel_cfg.config_path).await {
            Ok(t) => t,
            Err(e) => return IpcResponse::err(id, -32000, e.to_string()),
        };

        let peer_endpoint = match parse_peer_endpoint(&conf_text) {
            Some(ep) => ep,
            None => {
                return IpcResponse::err(id, -32602, "missing peer Endpoint".to_string());
            }
        };

        let (transport_resolved, transport_choice, merged_transport) =
            match self.transport_selector.resolve(
                &conf_text,
                &tunnel_cfg.transport,
                profile_transport.as_ref(),
                p.transport.as_ref(),
            ) {
                Ok(v) => v,
                Err(e) => return IpcResponse::err(id, -32000, e.to_string()),
            };

        if transport_resolved.fallback {
            let requested = transport_resolved
                .requested
                .unwrap_or(transport_resolved.kind);
            self.orchestrator
                .events()
                .publish(TunnelEvent::TransportFallback {
                    name: tunnel_cfg.name.clone(),
                    requested,
                    actual: transport_resolved.kind,
                    reason: transport_resolved
                        .fallback_reason
                        .clone()
                        .unwrap_or_else(|| "transport_unavailable".into()),
                });
        }

        self.orchestrator
            .events()
            .publish(TunnelEvent::TransportStarting {
                name: tunnel_cfg.name.clone(),
                kind: transport_resolved.kind,
            });

        let prepared = match self
            .transport_selector
            .prepare(
                transport_choice,
                &merged_transport,
                peer_endpoint,
                &tunnel_cfg.name,
                &conf_text,
                &transport_resolved,
            )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                self.orchestrator
                    .events()
                    .publish(TunnelEvent::TransportFailed {
                        name: tunnel_cfg.name.clone(),
                        kind: transport_resolved.kind,
                        reason: e.to_string(),
                        recoverable: false,
                    });
                return IpcResponse::err(id, -32000, e.to_string());
            }
        };

        if let Some(ref session) = prepared.transport_session {
            self.orchestrator
                .events()
                .publish(TunnelEvent::TransportConnected {
                    name: tunnel_cfg.name.clone(),
                    kind: session.kind,
                    local_endpoint: session.wireguard_endpoint.to_string(),
                    remote_transport: session.remote_transport.map(|a| a.to_string()),
                    protocol_version: if session.kind == TransportKind::Lwo {
                        Some(session.protocol_version)
                    } else {
                        None
                    },
                    wire_format: session.wire_format.clone(),
                });
        }

        let mut connect_cfg = tunnel_cfg.clone();
        connect_cfg.config_path = prepared.runtime_conf_path.clone();
        connect_cfg.mtu = prepared.effective_mtu;
        connect_cfg.transport = merged_transport;

        let (backend_resolved, backend_choice) = match self.selector.resolve(&connect_cfg) {
            Ok(v) => v,
            Err(e) => {
                self.rollback_transport(transport_choice, &prepared).await;
                return IpcResponse::err(id, -32000, e.to_string());
            }
        };

        if backend_resolved.fallback {
            self.orchestrator
                .events()
                .publish(TunnelEvent::BackendFallback {
                    name: tunnel_cfg.name.clone(),
                    requested: BackendKind::Awg,
                    actual: backend_resolved.kind,
                    reason: backend_resolved
                        .fallback_reason
                        .clone()
                        .unwrap_or_else(|| "awg_unavailable".into()),
                });
        }

        self.orchestrator.begin_connect(&tunnel_cfg.name).await;

        let connect_protocol_version = prepared
            .transport_session
            .as_ref()
            .map(|s| s.protocol_version);
        let connect_wire_format = prepared
            .transport_session
            .as_ref()
            .and_then(|s| s.wire_format.clone());

        match self.selector.up(backend_choice, &connect_cfg).await {
            Ok(handle) => match self.orchestrator.complete_connect(handle).await {
                Ok(h) => {
                    if let Some(active) = ActiveConnectSession::from_prepared(
                        prepared,
                        transport_choice,
                        tunnel_cfg.config_path.clone(),
                    ) {
                        self.active_session.set(active);
                    }
                    if let Err(e) = self.apply_full_policy().await {
                        return IpcResponse::err(id, -32000, e.to_string());
                    }
                    IpcResponse::ok(
                        id,
                        json!({
                            "name": h.name,
                            "if_index": h.if_index,
                            "backend": h.backend.as_str(),
                            "fallbackUsed": backend_resolved.fallback,
                            "transport": transport_resolved.kind.as_str(),
                            "transportFallbackUsed": transport_resolved.fallback,
                            "phantunActive": transport_resolved.kind == TransportKind::Phantun
                                && !transport_resolved.fallback,
                            "lwoActive": transport_resolved.kind == TransportKind::Lwo
                                && !transport_resolved.fallback,
                            "protocolVersion": connect_protocol_version,
                            "wireFormat": connect_wire_format,
                        }),
                    )
                }
                Err(e) => {
                    self.rollback_transport(transport_choice, &prepared).await;
                    IpcResponse::err(id, -32000, e.to_string())
                }
            },
            Err(e) => {
                self.rollback_transport(transport_choice, &prepared).await;
                IpcResponse::err(id, -32000, e.to_string())
            }
        }
    }

    async fn rollback_transport(
        &self,
        choice: TransportChoice,
        prepared: &routeguard_core::transport::PreparedConnect,
    ) {
        if let Some(ref session) = prepared.transport_session {
            let _ = self.transport_selector.down(choice, session).await;
            self.orchestrator
                .events()
                .publish(TunnelEvent::TransportDisconnected {
                    name: prepared.tunnel_config.name.clone(),
                    kind: session.kind,
                });
        }
    }

    async fn handle_disconnect(&self, id: u64) -> IpcResponse {
        #[cfg(windows)]
        {
            if let Some(session) = self.wfp.lock().await.as_mut() {
                let _ = session.disable_network_lock();
                let prev = self.session_routes.lock().unwrap().wfp_filter_ids.clone();
                let empty = PolicySnapshot::default();
                let _ = session.apply_split_policy(&empty, &prev);
            }
        }

        let handle = match self.orchestrator.active_handle().await {
            Some(h) => h,
            None => return IpcResponse::err(id, -32000, "no active tunnel".to_string()),
        };

        let choice = self.selector.choice_for(handle.backend);

        self.orchestrator
            .events()
            .publish(TunnelEvent::Disconnecting {
                name: handle.name.clone(),
            });

        if let Some(active) = self.active_session.take() {
            self.orchestrator
                .events()
                .publish(TunnelEvent::TransportDisconnected {
                    name: handle.name.clone(),
                    kind: active.transport_session.kind,
                });
            let _ = self
                .transport_selector
                .down(active.transport_choice, &active.transport_session)
                .await;
        }

        match self.selector.down(choice, &handle).await {
            Ok(()) => {
                let _ = self.orchestrator.disconnect_with_handle(handle).await;
                let _ = self.session_routes.lock().unwrap().clear(&self.routes);
                self.active_session.clear();
                IpcResponse::ok(id, json!({"disconnected": true}))
            }
            Err(e) => IpcResponse::err(id, -32000, e.to_string()),
        }
    }

    async fn handle_status(&self, id: u64) -> IpcResponse {
        let handle = self.orchestrator.active_handle().await;
        let status = handle
            .as_ref()
            .map(|h| {
                let choice = self.selector.choice_for(h.backend);
                self.selector.status(choice, h)
            })
            .unwrap_or(routeguard_core::tunnel::TunnelStatus::Disconnected);

        let stats = handle
            .as_ref()
            .and_then(|h| {
                let choice = self.selector.choice_for(h.backend);
                self.selector.stats(choice, h).ok()
            })
            .unwrap_or_default();

        let cfg = self.orchestrator.get_config().await;

        let nl = {
            #[cfg(windows)]
            {
                self.wfp
                    .lock()
                    .await
                    .as_ref()
                    .map(|s| s.network_lock_enabled())
                    .unwrap_or(false)
            }
            #[cfg(not(windows))]
            {
                false
            }
        };

        let active_transport = self.active_session.active();

        let session_state = self.orchestrator.session_state().await;
        let session_str = match session_state {
            routeguard_core::policy::SessionState::Disconnected => "disconnected",
            routeguard_core::policy::SessionState::Connecting => "connecting",
            routeguard_core::policy::SessionState::Connected => "connected",
            routeguard_core::policy::SessionState::Disconnecting => "disconnecting",
            routeguard_core::policy::SessionState::Reconnecting => "reconnecting",
            routeguard_core::policy::SessionState::Error => "error",
            routeguard_core::policy::SessionState::LockedDown => "locked_down",
        }
        .to_string();
        let rx_rate = *self.observability.last_rx_rate.lock().unwrap();
        let tx_rate = *self.observability.last_tx_rate.lock().unwrap();
        let transport_health = self
            .observability
            .transport_recovery
            .lock()
            .unwrap()
            .last_transport_health
            .clone();
        let health_score = self
            .observability
            .last_health
            .lock()
            .unwrap()
            .as_ref()
            .map(|h| h.score);

        let result = TunnelStatusResult {
            state: format!("{status:?}"),
            lifecycle: format!("{status:?}"),
            name: handle.as_ref().map(|h| h.name.clone()),
            if_index: handle.as_ref().map(|h| h.if_index),
            rx_bytes: stats.rx_bytes,
            tx_bytes: stats.tx_bytes,
            last_handshake_secs_ago: stats.last_handshake_secs_ago,
            peer_count: stats.peer_count,
            network_lock: nl || cfg.network_lock.enabled,
            backend: handle.as_ref().map(|h| h.backend.as_str().to_string()),
            awg_active: handle
                .as_ref()
                .map(|h| h.backend == BackendKind::Awg)
                .unwrap_or(false),
            fallback_used: active_transport
                .as_ref()
                .map(|a| a.resolved_transport.fallback)
                .unwrap_or(false),
            transport: active_transport.as_ref().map(|a| {
                transport_summary(
                    a.transport_session.kind,
                    a.transport_session.remote_transport.as_ref(),
                )
            }),
            phantun_active: active_transport
                .as_ref()
                .map(|a| a.transport_session.kind == TransportKind::Phantun)
                .unwrap_or(false),
            lwo_active: active_transport
                .as_ref()
                .map(|a| a.transport_session.kind == TransportKind::Lwo)
                .unwrap_or(false),
            transport_fallback_used: active_transport
                .as_ref()
                .map(|a| a.resolved_transport.fallback)
                .unwrap_or(false),
            local_endpoint: active_transport
                .as_ref()
                .map(|a| a.transport_session.wireguard_endpoint.to_string()),
            remote_transport: active_transport
                .as_ref()
                .and_then(|a| a.transport_session.remote_transport.map(|a| a.to_string())),
            protocol_version: active_transport
                .as_ref()
                .map(|a| a.transport_session.protocol_version),
            wire_format: active_transport
                .as_ref()
                .and_then(|a| a.transport_session.wire_format.clone()),
            session_state: Some(session_str),
            rx_rate_bps: Some(rx_rate * 8),
            tx_rate_bps: Some(tx_rate * 8),
            transport_health: if active_transport.is_some() {
                Some(transport_health)
            } else {
                None
            },
            health_score,
        };

        IpcResponse::ok(id, serde_json::to_value(result).unwrap_or(json!({})))
    }

    async fn handle_routing_reload(&self, id: u64) -> IpcResponse {
        match self.reload_routing_from_disk().await {
            Ok(()) => IpcResponse::ok(id, json!({"reloaded": true})),
            Err(e) => IpcResponse::err(id, -32000, e.to_string()),
        }
    }

    async fn handle_routing_get(&self, id: u64) -> IpcResponse {
        let cfg = self.orchestrator.get_config().await;
        let compiled = self.build_policy().await.ok();
        let result = RoutingListResult {
            mode: format!("{:?}", cfg.routing.mode),
            rules: serde_json::to_value(&cfg.routing).unwrap_or(json!({})),
            compiled: compiled.and_then(|p| serde_json::to_value(p).ok()),
        };
        IpcResponse::ok(id, serde_json::to_value(result).unwrap_or(json!({})))
    }

    async fn handle_routing_add_app(&self, id: u64, params: Value) -> IpcResponse {
        let p: AddAppRuleParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };

        let mode = match parse_rule_mode(&p.mode) {
            Ok(m) => m,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };

        let mut cfg = self.orchestrator.get_config().await;
        let previous = cfg.clone();
        let priority = p
            .priority
            .unwrap_or_else(|| default_priority_for_mode(&cfg, mode));

        let rule = match add_app_rule(
            &mut cfg,
            AddAppRuleRequest {
                path: p.path,
                mode,
                priority,
            },
        ) {
            Ok(r) => r,
            Err(e) => return IpcResponse::err(id, -32602, e),
        };

        if let Err(e) = self.orchestrator.set_config(cfg.clone()).await {
            return IpcResponse::err(id, -32000, e.to_string());
        }

        match RoutingEngine::from_config(&cfg) {
            Ok(engine) => *self.routing.write().await = engine,
            Err(e) => {
                let _ = self.orchestrator.set_config(previous).await;
                return IpcResponse::err(id, -32000, e);
            }
        }

        if let Err(e) = self.apply_split_policy().await {
            let _ = self.orchestrator.set_config(previous).await;
            if let Ok(eng) = RoutingEngine::from_config(&self.orchestrator.get_config().await) {
                *self.routing.write().await = eng;
            }
            return IpcResponse::err(id, -32000, e.to_string());
        }

        IpcResponse::ok(id, serde_json::to_value(&rule).unwrap_or(json!({})))
    }

    async fn handle_routing_remove_app(&self, id: u64, params: Value) -> IpcResponse {
        let p: RemoveAppRuleParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };

        let mut cfg = self.orchestrator.get_config().await;
        let previous = cfg.clone();

        let removed = match remove_app_rule(&mut cfg, &p.path) {
            Ok(r) => r,
            Err(e) => return IpcResponse::err(id, -32602, e),
        };

        if let Err(e) = self.orchestrator.set_config(cfg.clone()).await {
            return IpcResponse::err(id, -32000, e.to_string());
        }

        match RoutingEngine::from_config(&cfg) {
            Ok(engine) => *self.routing.write().await = engine,
            Err(e) => {
                let _ = self.orchestrator.set_config(previous).await;
                return IpcResponse::err(id, -32000, e);
            }
        }

        if let Err(e) = self.apply_split_policy().await {
            let _ = self.orchestrator.set_config(previous).await;
            if let Ok(eng) = RoutingEngine::from_config(&self.orchestrator.get_config().await) {
                *self.routing.write().await = eng;
            }
            return IpcResponse::err(id, -32000, e.to_string());
        }

        IpcResponse::ok(id, serde_json::to_value(&removed).unwrap_or(json!({})))
    }

    async fn handle_routing_test(&self, id: u64, params: Value) -> IpcResponse {
        let p: RoutingTestParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };

        let ip: std::net::IpAddr = match p.remote_ip.parse() {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };

        let engine = self.routing.read().await;
        let decision = engine.decide(&FlowContext {
            app_path: p.app_path,
            remote_ip: ip,
            remote_port: 443,
            protocol: Protocol::Tcp,
            domain: p.domain,
        });

        let result = RoutingTestResult {
            target: format!("{:?}", decision.target),
            reason: decision.reason,
        };
        IpcResponse::ok(id, serde_json::to_value(result).unwrap_or(json!({})))
    }

    async fn handle_nl_enable(&self, id: u64) -> IpcResponse {
        let mut cfg = self.orchestrator.get_config().await;
        cfg.network_lock.enabled = true;
        let _ = self.orchestrator.set_config(cfg).await;
        if let Err(e) = self.apply_full_policy().await {
            return IpcResponse::err(id, -32000, e.to_string());
        }
        self.event_store
            .push("network_lock.enabled", json!({"active": true}));
        IpcResponse::ok(id, json!({"enabled": true}))
    }

    async fn handle_nl_disable(&self, id: u64) -> IpcResponse {
        let mut cfg = self.orchestrator.get_config().await;
        cfg.network_lock.enabled = false;
        let _ = self.orchestrator.set_config(cfg).await;

        #[cfg(windows)]
        {
            if let Some(session) = self.wfp.lock().await.as_mut() {
                if let Err(e) = session.disable_network_lock() {
                    return IpcResponse::err(id, -32000, e.to_string());
                }
            }
        }

        self.event_store
            .push("network_lock.disabled", json!({"active": false}));
        IpcResponse::ok(id, json!({"enabled": false}))
    }

    async fn handle_nl_status(&self, id: u64) -> IpcResponse {
        let cfg = self.orchestrator.get_config().await;
        #[cfg(windows)]
        let active = self
            .wfp
            .lock()
            .await
            .as_ref()
            .map(|s| s.network_lock_enabled())
            .unwrap_or(false);
        #[cfg(not(windows))]
        let active = false;

        IpcResponse::ok(
            id,
            json!({"configured": cfg.network_lock.enabled, "active": active}),
        )
    }

    async fn handle_config_get(&self, id: u64) -> IpcResponse {
        let cfg = self.orchestrator.get_config().await;
        match cfg.to_toml() {
            Ok(s) => IpcResponse::ok(id, json!({"toml": s})),
            Err(e) => IpcResponse::err(id, -32000, e.to_string()),
        }
    }

    async fn handle_config_set(&self, id: u64, params: Value) -> IpcResponse {
        let toml_str = match params.get("toml").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return IpcResponse::err(id, -32602, "missing toml field"),
        };
        match AppConfig::from_toml(toml_str) {
            Ok(cfg) => {
                if let Err(e) = self.orchestrator.set_config(cfg.clone()).await {
                    return IpcResponse::err(id, -32000, e.to_string());
                }
                if let Ok(engine) = RoutingEngine::from_config(&cfg) {
                    *self.routing.write().await = engine;
                }
                if let Err(e) = self.apply_split_policy().await {
                    return IpcResponse::err(id, -32000, e.to_string());
                }
                IpcResponse::ok(id, json!({"saved": true}))
            }
            Err(e) => IpcResponse::err(id, -32602, e.to_string()),
        }
    }

    async fn handle_service_ping(&self, id: u64) -> IpcResponse {
        let result = ServicePingResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            elevated: true,
        };
        IpcResponse::ok(id, serde_json::to_value(result).unwrap_or(json!({})))
    }

    async fn handle_service_capabilities(&self, id: u64) -> IpcResponse {
        let cfg = self.orchestrator.get_config().await;
        let has_domain_rules = !cfg.routing.domain_rules.is_empty();
        let dns_enabled = cfg.routing.domain_dns.enabled;
        let tunnel_connected = self.has_active_tunnel().await;
        let effective =
            self.domain_mgr
                .is_effective(has_domain_rules, dns_enabled, tunnel_connected);

        #[cfg(windows)]
        let callout_present = probe_callout_driver();
        #[cfg(windows)]
        let awg_present = self.selector.probe_awg();
        #[cfg(windows)]
        let awg_params: Option<Vec<String>> = Some(
            self.selector
                .awg_param_names()
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        );
        #[cfg(windows)]
        let phantun_present = self.transport_selector.probe_phantun();
        #[cfg(windows)]
        let lwo_present = self.transport_selector.probe_lwo();
        #[cfg(windows)]
        let transport_capabilities: Option<Vec<TransportCapabilityEntry>> = Some(
            self.transport_selector
                .capabilities()
                .into_iter()
                .map(|c| TransportCapabilityEntry {
                    kind: c.kind.as_str().to_string(),
                    available: c.available,
                    default: c.kind == TransportKind::DirectUdp,
                    supports_ipv6: c.supports_ipv6,
                    binary_present: if c.requires_binary {
                        Some(c.available)
                    } else {
                        None
                    },
                    binary_path: c.binary_path.clone(),
                    max_mtu_delta: Some(c.default_mtu_delta),
                    protocol_version: c.protocol_version,
                    wire_format: c.wire_format.clone(),
                })
                .collect(),
        );
        #[cfg(windows)]
        let features = ServiceFeatures {
            app_split_tunnel: true,
            ip_routing: true,
            domain_routing: true,
            domain_routing_effective: effective,
            network_lock_wfp: true,
            tunnel_backend: true,
            event_stream: true,
            awg: awg_present,
            phantun: phantun_present,
            lwo: lwo_present,
            transports: true,
            callout_driver: callout_present,
            awg_params,
            observability: true,
            diagnostics_export: true,
            metrics_history: true,
        };
        #[cfg(not(windows))]
        let transport_capabilities: Option<Vec<TransportCapabilityEntry>> = None;
        #[cfg(not(windows))]
        let features = ServiceFeatures {
            app_split_tunnel: false,
            ip_routing: false,
            domain_routing: false,
            domain_routing_effective: false,
            network_lock_wfp: false,
            tunnel_backend: false,
            event_stream: true,
            awg: false,
            phantun: false,
            lwo: false,
            transports: false,
            callout_driver: false,
            awg_params: None,
            observability: true,
            diagnostics_export: false,
            metrics_history: false,
        };

        let observability = Some(ObservabilityFeatures {
            schema_version: 1,
            snapshot_sections: vec![
                "tunnel".into(),
                "transport".into(),
                "routing".into(),
                "networkLock".into(),
                "dns".into(),
                "capabilities".into(),
                "health".into(),
            ],
            history_metrics: routeguard_core::observability::KNOWN_METRICS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            export_tiers: vec!["sanitized".into(), "support".into(), "full".into()],
        });

        let result = ServiceCapabilitiesResult {
            schema_version: 3,
            features,
            limits: ServiceLimits {
                max_app_rules: routeguard_routing::MAX_APP_RULES as u32,
            },
            routing_modes: vec!["full_tunnel".into(), "split_include".into()],
            transport_capabilities,
            future_transports: Some(vec!["tls".into(), "websocket".into()]),
            observability,
        };
        IpcResponse::ok(id, serde_json::to_value(result).unwrap_or(json!({})))
    }

    async fn handle_routing_import_rules(&self, id: u64, params: Value) -> IpcResponse {
        let p: ImportRulesParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };

        let mut cfg = self.orchestrator.get_config().await;
        let previous = cfg.clone();

        if p.clear {
            cfg.routing = routeguard_core::config::RoutingConfig::default();
        } else {
            cfg.routing.mode = match p.mode.to_ascii_lowercase().as_str() {
                "split_include" => RoutingMode::SplitInclude,
                _ => RoutingMode::FullTunnel,
            };

            cfg.routing.app_rules = p
                .app_rules
                .into_iter()
                .filter(|r| r.enabled)
                .filter_map(|r| {
                    let mode = parse_rule_mode(&r.mode).ok()?;
                    Some(AppRule {
                        priority: r.priority.unwrap_or(100),
                        mode,
                        path: r.path,
                    })
                })
                .collect();

            cfg.routing.ip_rules = p
                .ip_rules
                .into_iter()
                .filter(|r| r.enabled)
                .filter_map(|r| {
                    Some(IpRule {
                        priority: r.priority.unwrap_or(100),
                        cidr: r.cidr,
                        target: parse_route_target(&r.target).ok()?,
                    })
                })
                .collect();

            cfg.routing.domain_rules = p
                .domain_rules
                .into_iter()
                .filter(|r| r.enabled)
                .filter_map(|r| {
                    Some(DomainRule {
                        priority: r.priority.unwrap_or(100),
                        pattern: r.pattern,
                        target: parse_route_target(&r.target).ok()?,
                    })
                })
                .collect();
        }

        if let Some(ctx) = p.tunnel_context {
            *self.external_tunnel.write().await = Some(ctx);
        }

        if let Err(e) = self.orchestrator.set_config(cfg.clone()).await {
            return IpcResponse::err(id, -32000, e.to_string());
        }

        match RoutingEngine::from_config(&cfg) {
            Ok(engine) => *self.routing.write().await = engine,
            Err(e) => {
                let _ = self.orchestrator.set_config(previous).await;
                return IpcResponse::err(id, -32000, e);
            }
        }

        self.domain_mgr.rebuild_rules(&cfg.routing.domain_rules);

        if let Err(e) = self.apply_split_policy().await {
            let _ = self.orchestrator.set_config(previous).await;
            if let Ok(eng) = RoutingEngine::from_config(&self.orchestrator.get_config().await) {
                *self.routing.write().await = eng;
            }
            return IpcResponse::err(id, -32000, e.to_string());
        }

        self.emit_routing_reloaded(
            cfg.routing.app_rules.len(),
            cfg.routing.domain_rules.len(),
            self.domain_mgr.resolved_count(),
        );

        IpcResponse::ok(
            id,
            json!({
                "imported": true,
                "appRules": cfg.routing.app_rules.len(),
                "ipRules": cfg.routing.ip_rules.len(),
                "domainRules": cfg.routing.domain_rules.len(),
                "domainRoutes": self.domain_mgr.resolved_count(),
            }),
        )
    }

    async fn handle_routing_set_tunnel_context(&self, id: u64, params: Value) -> IpcResponse {
        let ctx: TunnelContextParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };

        *self.external_tunnel.write().await = Some(ctx.clone());

        if let Err(e) = self.apply_split_policy().await {
            return IpcResponse::err(id, -32000, e.to_string());
        }

        IpcResponse::ok(id, json!({"ok": true, "connected": ctx.connected}))
    }

    async fn handle_events_poll(&self, id: u64, params: Value) -> IpcResponse {
        let p: EventsPollParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };

        let events = self.event_store.poll(p.since_id, p.limit.min(256));
        let latest_id = self.event_store.latest_id();
        IpcResponse::ok(id, json!({"events": events, "latestId": latest_id}))
    }

    async fn handle_domain_status(&self, id: u64) -> IpcResponse {
        let cfg = self.orchestrator.get_config().await;
        let effective = self.domain_mgr.is_effective(
            !cfg.routing.domain_rules.is_empty(),
            cfg.routing.domain_dns.enabled,
            self.has_active_tunnel().await,
        );

        #[cfg(windows)]
        let (kernel_redirect, redirect_stats, driver_present) = {
            let mgr = self.dns_callout.lock().await;
            (
                mgr.kernel_active(),
                mgr.get_stats().ok(),
                mgr.driver_present(),
            )
        };

        let mut domain = self.domain_mgr.status_json();
        if let Some(obj) = domain.as_object_mut() {
            #[cfg(windows)]
            {
                obj.insert("kernelRedirect".into(), json!(kernel_redirect));
                obj.insert("driverPresent".into(), json!(driver_present));
                if let Some(stats) = redirect_stats {
                    obj.insert(
                        "redirectStats".into(),
                        serde_json::to_value(stats).unwrap_or(json!({})),
                    );
                }
            }
            #[cfg(not(windows))]
            {
                obj.insert("kernelRedirect".into(), json!(false));
                obj.insert("driverPresent".into(), json!(false));
            }
        }

        IpcResponse::ok(
            id,
            json!({
                "effective": effective,
                "domain": domain,
            }),
        )
    }

    fn emit_routing_reloaded(&self, rule_count: usize, domain_rules: usize, domain_routes: usize) {
        let payload = json!({
            "reason": "import",
            "ruleCount": rule_count,
            "domainRules": domain_rules,
            "domainRoutes": domain_routes,
        });
        self.event_store.push("routing.reloaded", payload);
    }

    async fn handle_profile_list(&self, id: u64) -> IpcResponse {
        match profile_store::list_profiles() {
            Ok(profiles) => IpcResponse::ok(id, json!({"profiles": profiles})),
            Err(e) => IpcResponse::err(id, -32000, e.to_string()),
        }
    }

    async fn handle_profile_get(&self, id: u64, params: Value) -> IpcResponse {
        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            return IpcResponse::err(id, -32602, "name required".to_string());
        }
        match profile_store::get_profile(name) {
            Ok(Some(p)) => IpcResponse::ok(id, json!({"profile": p})),
            Ok(None) => IpcResponse::err(id, -32000, "profile not found".to_string()),
            Err(e) => IpcResponse::err(id, -32000, e.to_string()),
        }
    }

    async fn handle_profile_import(&self, id: u64, params: Value) -> IpcResponse {
        let p: ProfileImportParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };
        match profile_store::import_profile(p) {
            Ok(profile) => {
                self.event_store.push(
                    "tunnel.profile.imported",
                    json!({"name": profile.name, "kind": profile.kind}),
                );
                IpcResponse::ok(id, json!({"profile": profile}))
            }
            Err(e) => IpcResponse::err(id, -32000, e.to_string()),
        }
    }

    async fn handle_profile_export(&self, id: u64, params: Value) -> IpcResponse {
        let p: ProfileExportParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };
        match profile_store::export_profile(p) {
            Ok(text) => IpcResponse::ok(id, json!({"confText": text})),
            Err(e) => IpcResponse::err(id, -32000, e.to_string()),
        }
    }

    async fn handle_profile_validate(&self, id: u64, params: Value) -> IpcResponse {
        let p: ProfileValidateParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };
        let result = profile_store::validate_profile(p);
        IpcResponse::ok(id, serde_json::to_value(result).unwrap_or(json!({})))
    }

    async fn handle_profile_delete(&self, id: u64, params: Value) -> IpcResponse {
        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            return IpcResponse::err(id, -32602, "name required".to_string());
        }
        match profile_store::delete_profile(name) {
            Ok(()) => IpcResponse::ok(id, json!({"deleted": true})),
            Err(e) => IpcResponse::err(id, -32000, e.to_string()),
        }
    }

    async fn handle_observability_snapshot(&self, id: u64, params: Value) -> IpcResponse {
        let p: ObservabilitySnapshotParams = serde_json::from_value(params).unwrap_or_default();
        let sections = p.sections.as_deref();
        let snap = collect_snapshot(self, sections).await;
        IpcResponse::ok(id, serde_json::to_value(snap).unwrap_or(json!({})))
    }

    async fn handle_observability_history(&self, id: u64, params: Value) -> IpcResponse {
        let p: ObservabilityHistoryParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };
        let series = self
            .observability
            .metrics
            .query(&p.metric, &p.window, &p.resolution);
        let result = ObservabilityHistoryResult {
            metric: p.metric,
            window: p.window,
            resolution: p.resolution,
            series,
        };
        IpcResponse::ok(id, serde_json::to_value(result).unwrap_or(json!({})))
    }

    async fn handle_service_health(&self, id: u64) -> IpcResponse {
        let sections = vec!["health".to_string()];
        let snap = collect_snapshot(self, Some(&sections)).await;
        IpcResponse::ok(id, serde_json::to_value(snap.health).unwrap_or(json!({})))
    }

    async fn handle_metrics_list(&self, id: u64) -> IpcResponse {
        let result = MetricsListResult {
            metrics: list_metrics(),
        };
        IpcResponse::ok(id, serde_json::to_value(result).unwrap_or(json!({})))
    }

    async fn handle_diagnostics_export(&self, id: u64, params: Value) -> IpcResponse {
        let p: DiagnosticsExportParams = match serde_json::from_value(params) {
            Ok(v) => v,
            Err(e) => return IpcResponse::err(id, -32602, e.to_string()),
        };
        if p.tier == "full" && !diagnostics_full_allowed() {
            return IpcResponse::err(
                id,
                -32001,
                "full diagnostics tier requires admin elevation (set ROUTE_GUARD_FULL_DIAGNOSTICS=1)".to_string(),
            );
        }
        match export_diagnostics(self, &p).await {
            Ok(r) => IpcResponse::ok(id, serde_json::to_value(r).unwrap_or(json!({}))),
            Err(e) => IpcResponse::err(id, -32000, e.to_string()),
        }
    }

    async fn handle_logs_tail(&self, id: u64, params: Value) -> IpcResponse {
        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
        let lines = self.observability.logs.tail(limit);
        IpcResponse::ok(id, json!({ "lines": lines }))
    }
}

fn diagnostics_full_allowed() -> bool {
    std::env::var("ROUTE_GUARD_FULL_DIAGNOSTICS").as_deref() == Ok("1")
}
