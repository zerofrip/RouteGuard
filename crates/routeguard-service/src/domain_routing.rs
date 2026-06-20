//! Orchestrates domain DNS cache, host routes, persistence, and events.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use routeguard_core::config::{DomainRule, RouteTarget};
use routeguard_core::events::EventStore;
use routeguard_core::policy::PolicySnapshot;
use routeguard_platform::{RouteTableManager, SessionRoutes};
use routeguard_routing::{
    DomainRouteStore, DomainRouteStoreConfig, ResolvedIpEntry, RoutingEngine,
};
use serde_json::json;

pub fn default_cache_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("ProgramData") {
            return PathBuf::from(p)
                .join("RouteGuard")
                .join("domain_cache.json");
        }
    }
    PathBuf::from("domain_cache.json")
}

pub struct DomainRoutingManager {
    store: Mutex<DomainRouteStore>,
    event_store: Arc<EventStore>,
    routing: Arc<tokio::sync::RwLock<RoutingEngine>>,
    cache_path: PathBuf,
    dns_redirect_active: AtomicBool,
    explicit_proxy: AtomicBool,
    store_config: DomainRouteStoreConfig,
}

impl DomainRoutingManager {
    pub fn new(
        event_store: Arc<EventStore>,
        routing: Arc<tokio::sync::RwLock<RoutingEngine>>,
        store_config: DomainRouteStoreConfig,
    ) -> Self {
        let cache_path = default_cache_path();
        let mut mgr = Self {
            store: Mutex::new(DomainRouteStore::new(store_config.clone())),
            event_store,
            routing,
            cache_path,
            dns_redirect_active: AtomicBool::new(false),
            explicit_proxy: AtomicBool::new(false),
            store_config,
        };
        mgr.load_persisted();
        mgr
    }

    pub fn set_explicit_proxy(&self, enabled: bool) {
        self.explicit_proxy.store(enabled, Ordering::SeqCst);
    }

    pub fn set_dns_redirect_active(&self, active: bool) {
        self.dns_redirect_active.store(active, Ordering::SeqCst);
    }

    pub fn dns_redirect_active(&self) -> bool {
        self.dns_redirect_active.load(Ordering::SeqCst)
    }

    pub fn is_effective(
        &self,
        has_domain_rules: bool,
        dns_enabled: bool,
        tunnel_connected: bool,
    ) -> bool {
        if !has_domain_rules || !dns_enabled {
            return false;
        }
        let ingress = self.dns_redirect_active() || self.explicit_proxy.load(Ordering::SeqCst);
        if !ingress {
            return false;
        }
        tunnel_connected || self.only_bypass_targets()
    }

    fn only_bypass_targets(&self) -> bool {
        let store = self.store.lock().unwrap();
        !store.rules().is_empty()
            && store
                .rules()
                .iter()
                .all(|r| r.target == RouteTarget::Bypass)
    }

    pub fn rebuild_rules(&self, rules: &[DomainRule]) {
        let mut store = self.store.lock().unwrap();
        store.set_rules(rules);
        let pruned = store.prune_unmatched_rules();
        drop(store);
        for entry in pruned {
            self.emit_route_expired(&entry);
        }
        self.sync_engine();
    }

    fn sync_engine(&self) {
        self.sync_to_engine(&self.routing);
    }

    pub fn on_dns_response(
        &self,
        domain: &str,
        records: &[(IpAddr, u32)],
        session_routes: &Mutex<SessionRoutes>,
        routes: &RouteTableManager,
        policy: &PolicySnapshot,
    ) {
        if records.is_empty() {
            return;
        }

        let rule = {
            let store = self.store.lock().unwrap();
            store.match_domain(domain).cloned()
        };
        let Some(rule) = rule else {
            return;
        };

        let diff = {
            let mut store = self.store.lock().unwrap();
            store.apply_resolved(domain, records, &rule)
        };

        self.sync_engine();

        let tunnel_if = policy.tunnel_if_index.unwrap_or(0);
        let physical_if = policy.physical_if_index.unwrap_or(0);

        if tunnel_if != 0 || physical_if != 0 {
            let mut sr = session_routes.lock().unwrap();
            for entry in &diff.added {
                let _ = sr.install_domain_route(
                    routes,
                    entry.ip,
                    entry.target,
                    tunnel_if,
                    physical_if,
                    entry.expires_at,
                );
                self.emit_route_added(entry);
            }
            for entry in &diff.removed {
                let _ = sr.remove_domain_route(routes, entry.ip);
                self.emit_route_expired(entry);
            }
        }

        if !diff.added.is_empty() || !diff.refreshed.is_empty() {
            let ips: Vec<_> = records.iter().map(|(ip, _)| *ip).collect();
            let ttl = records.first().map(|(_, t)| *t).unwrap_or(300);
            self.event_store.push(
                "routing.dns.resolved",
                json!({
                    "domain": domain,
                    "ips": ips,
                    "ttlSecs": ttl,
                    "pattern": rule.pattern,
                    "target": format!("{:?}", rule.target).to_ascii_lowercase(),
                }),
            );
        }

        let _ = self.persist();
    }

    pub fn purge_expired(&self, session_routes: &Mutex<SessionRoutes>, routes: &RouteTableManager) {
        let expired = {
            let mut store = self.store.lock().unwrap();
            store.purge_expired()
        };

        if !expired.is_empty() {
            let mut sr = session_routes.lock().unwrap();
            for entry in &expired {
                let _ = sr.remove_domain_route(routes, entry.ip);
                self.emit_route_expired(entry);
            }
            self.sync_engine();
            let _ = self.persist();
        } else {
            let _ = session_routes
                .lock()
                .unwrap()
                .purge_expired_domain_routes(routes);
        }
    }

    pub fn clear(&self, session_routes: &Mutex<SessionRoutes>, routes: &RouteTableManager) {
        {
            let mut store = self.store.lock().unwrap();
            store.clear();
        }
        let _ = session_routes.lock().unwrap().clear_domain_routes(routes);
        self.sync_engine();
        let _ = self.persist();
    }

    pub fn snapshot_store(&self) -> DomainRouteStore {
        self.store.lock().unwrap().clone()
    }

    pub fn rule_count(&self) -> usize {
        self.store.lock().unwrap().rules().len()
    }

    pub fn resolved_count(&self) -> usize {
        self.store.lock().unwrap().resolved_count()
    }

    pub fn status_json(&self) -> serde_json::Value {
        let store = self.store.lock().unwrap();
        let sample: Vec<_> = store
            .entries()
            .take(20)
            .map(|e| {
                json!({
                    "ip": e.ip.to_string(),
                    "domain": e.domain,
                    "pattern": e.pattern,
                    "target": format!("{:?}", e.target).to_ascii_lowercase(),
                    "expiresAt": e.expires_at,
                    "ttlSecs": e.ttl_secs,
                })
            })
            .collect();
        json!({
            "rules": store.rules().len(),
            "resolvedIps": store.resolved_count(),
            "routes": store.resolved_count(),
            "domains": store.domain_count(),
            "generation": store.generation(),
            "redirectActive": self.dns_redirect_active(),
            "explicitProxy": self.explicit_proxy.load(Ordering::SeqCst),
            "sample": sample,
        })
    }

    pub fn load_persisted(&mut self) {
        if !self.cache_path.exists() {
            return;
        }
        if let Ok(data) = std::fs::read_to_string(&self.cache_path) {
            match DomainRouteStore::load_persisted(&data, self.store_config.clone()) {
                Ok(loaded) => {
                    let count = loaded.resolved_count();
                    *self.store.lock().unwrap() = loaded;
                    self.event_store.push(
                        "routing.domain_recovered",
                        json!({ "count": count, "generation": self.store.lock().unwrap().generation() }),
                    );
                    self.sync_engine();
                }
                Err(e) => tracing::warn!("domain cache load failed: {e}"),
            }
        }
    }

    pub fn persist(&self) -> Result<(), String> {
        if let Some(parent) = self.cache_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = self.store.lock().unwrap().persist_json()?;
        std::fs::write(&self.cache_path, json).map_err(|e| e.to_string())
    }

    pub fn reinstall_routes_from_cache(
        &self,
        session_routes: &Mutex<SessionRoutes>,
        routes: &RouteTableManager,
        policy: &PolicySnapshot,
    ) {
        let tunnel_if = policy.tunnel_if_index.unwrap_or(0);
        let physical_if = policy.physical_if_index.unwrap_or(0);
        if tunnel_if == 0 && physical_if == 0 {
            return;
        }

        let entries: Vec<ResolvedIpEntry> = self.store.lock().unwrap().entries().cloned().collect();

        let mut sr = session_routes.lock().unwrap();
        for entry in entries {
            let _ = sr.install_domain_route(
                routes,
                entry.ip,
                entry.target,
                tunnel_if,
                physical_if,
                entry.expires_at,
            );
        }
    }

    pub fn sync_to_engine(&self, routing: &tokio::sync::RwLock<RoutingEngine>) {
        if let Ok(mut eng) = routing.try_write() {
            let store = self.store.lock().unwrap();
            eng.sync_domain_store(&store);
        }
    }

    fn emit_route_added(&self, entry: &ResolvedIpEntry) {
        self.event_store.push(
            "routing.domain_route_added",
            json!({
                "ip": entry.ip.to_string(),
                "domain": entry.domain,
                "target": format!("{:?}", entry.target).to_ascii_lowercase(),
                "expiresAt": entry.expires_at,
            }),
        );
    }

    fn emit_route_expired(&self, entry: &ResolvedIpEntry) {
        self.event_store.push(
            "routing.domain_route_expired",
            json!({
                "ip": entry.ip.to_string(),
                "domain": entry.domain,
            }),
        );
    }
}
