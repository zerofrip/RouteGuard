use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PIPE_NAME: &str = r"\\.\pipe\RouteGuard";

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl IpcRequest {
    pub fn new(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcError {
    pub code: i32,
    pub message: String,
}

impl IpcResponse {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(IpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// IPC method names.
pub mod methods {
    pub const TUNNEL_CONNECT: &str = "tunnel.connect";
    pub const TUNNEL_DISCONNECT: &str = "tunnel.disconnect";
    pub const TUNNEL_STATUS: &str = "tunnel.status";
    pub const ROUTING_RELOAD: &str = "routing.reload";
    pub const ROUTING_GET: &str = "routing.get";
    pub const ROUTING_ADD_APP: &str = "routing.add_app";
    pub const ROUTING_REMOVE_APP: &str = "routing.remove_app";
    pub const ROUTING_TEST: &str = "routing.test";
    pub const NETWORK_LOCK_ENABLE: &str = "network_lock.enable";
    pub const NETWORK_LOCK_DISABLE: &str = "network_lock.disable";
    pub const NETWORK_LOCK_STATUS: &str = "network_lock.status";
    pub const LOGS_TAIL: &str = "logs.tail";
    pub const CONFIG_GET: &str = "config.get";
    pub const CONFIG_SET: &str = "config.set";
    pub const SERVICE_PING: &str = "service.ping";
    pub const SERVICE_CAPABILITIES: &str = "service.capabilities";
    pub const ROUTING_IMPORT_RULES: &str = "routing.import_rules";
    pub const ROUTING_SET_TUNNEL_CONTEXT: &str = "routing.set_tunnel_context";
    pub const EVENTS_POLL: &str = "events.poll";
    pub const DOMAIN_STATUS: &str = "domain.status";
    pub const TUNNEL_PROFILE_LIST: &str = "tunnel.profile.list";
    pub const TUNNEL_PROFILE_GET: &str = "tunnel.profile.get";
    pub const TUNNEL_PROFILE_IMPORT: &str = "tunnel.profile.import";
    pub const TUNNEL_PROFILE_EXPORT: &str = "tunnel.profile.export";
    pub const TUNNEL_PROFILE_VALIDATE: &str = "tunnel.profile.validate";
    pub const TUNNEL_PROFILE_DELETE: &str = "tunnel.profile.delete";
    pub const OBSERVABILITY_SNAPSHOT: &str = "observability.snapshot";
    pub const OBSERVABILITY_HISTORY: &str = "observability.history";
    pub const SERVICE_HEALTH: &str = "service.health";
    pub const METRICS_LIST: &str = "metrics.list";
    pub const DIAGNOSTICS_EXPORT: &str = "diagnostics.export";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectParams {
    pub name: Option<String>,
    pub config_path: Option<PathBuf>,
    #[serde(default)]
    pub profile_name: Option<String>,
    #[serde(default)]
    pub transport: Option<crate::transport::TunnelTransportConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatusResult {
    pub state: String,
    pub lifecycle: String,
    pub name: Option<String>,
    pub if_index: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_secs_ago: Option<u64>,
    pub peer_count: usize,
    pub network_lock: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default)]
    pub awg_active: bool,
    #[serde(default)]
    pub fallback_used: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default)]
    pub phantun_active: bool,
    #[serde(default)]
    pub lwo_active: bool,
    #[serde(default)]
    pub transport_fallback_used: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_rate_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_rate_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_health: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_score: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingTestParams {
    pub app_path: Option<PathBuf>,
    pub remote_ip: String,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingTestResult {
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddAppRuleParams {
    pub path: PathBuf,
    pub mode: String,
    #[serde(default)]
    pub priority: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveAppRuleParams {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingListResult {
    pub mode: String,
    pub rules: serde_json::Value,
    pub compiled: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePingResult {
    pub version: String,
    pub uptime_secs: u64,
    pub elevated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceCapabilitiesResult {
    pub schema_version: u32,
    pub features: ServiceFeatures,
    pub limits: ServiceLimits,
    pub routing_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_capabilities: Option<Vec<TransportCapabilityEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub future_transports: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<crate::observability::ObservabilityFeatures>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportCapabilityEntry {
    pub kind: String,
    pub available: bool,
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub supports_ipv6: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mtu_delta: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceFeatures {
    pub app_split_tunnel: bool,
    pub ip_routing: bool,
    pub domain_routing: bool,
    pub domain_routing_effective: bool,
    pub network_lock_wfp: bool,
    pub tunnel_backend: bool,
    pub event_stream: bool,
    pub awg: bool,
    pub phantun: bool,
    #[serde(default)]
    pub lwo: bool,
    #[serde(default)]
    pub transports: bool,
    pub callout_driver: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awg_params: Option<Vec<String>>,
    #[serde(default)]
    pub observability: bool,
    #[serde(default)]
    pub diagnostics_export: bool,
    #[serde(default)]
    pub metrics_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceLimits {
    pub max_app_rules: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRulesParams {
    #[serde(default)]
    pub clear: bool,
    #[serde(default = "default_full_tunnel")]
    pub mode: String,
    #[serde(default, rename = "appRules")]
    pub app_rules: Vec<ImportAppRule>,
    #[serde(default, rename = "ipRules")]
    pub ip_rules: Vec<ImportIpRule>,
    #[serde(default, rename = "domainRules")]
    pub domain_rules: Vec<ImportDomainRule>,
    #[serde(default, rename = "tunnelContext")]
    pub tunnel_context: Option<TunnelContextParams>,
}

fn default_full_tunnel() -> String {
    "full_tunnel".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportAppRule {
    pub path: PathBuf,
    pub mode: String,
    #[serde(default)]
    pub priority: Option<u16>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportIpRule {
    pub cidr: String,
    pub target: String,
    #[serde(default)]
    pub priority: Option<u16>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDomainRule {
    pub pattern: String,
    pub target: String,
    #[serde(default)]
    pub priority: Option<u16>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelContextParams {
    pub name: String,
    #[serde(default, rename = "adapterName")]
    pub adapter_name: Option<String>,
    #[serde(default, rename = "ifIndex")]
    pub if_index: Option<u32>,
    #[serde(default, rename = "endpointIp")]
    pub endpoint_ip: Option<String>,
    #[serde(default)]
    pub connected: bool,
    #[serde(default, rename = "backendKind")]
    pub backend_kind: Option<String>,
    #[serde(default, rename = "transportKind")]
    pub transport_kind: Option<String>,
    #[serde(default, rename = "transportRemote")]
    pub transport_remote: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsPollParams {
    #[serde(default, rename = "sinceId")]
    pub since_id: u64,
    #[serde(default = "default_poll_limit")]
    pub limit: usize,
}

fn default_poll_limit() -> usize {
    64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsPollResult {
    pub events: Vec<crate::events::EventRecord>,
    #[serde(rename = "latestId")]
    pub latest_id: u64,
}

/// Trait implemented by the service-side IPC handler.
#[async_trait::async_trait]
pub trait IpcHandler: Send + Sync {
    async fn handle(&self, req: IpcRequest) -> IpcResponse;
}

/// Server-side IPC (implemented in routeguard-service).
pub struct IpcServer;

/// Client-side IPC (implemented in routeguard-cli).
pub struct IpcClient;

impl IpcClient {
    pub async fn call(req: IpcRequest) -> crate::Result<IpcResponse> {
        #[cfg(windows)]
        {
            crate::ipc::client::call(req).await
        }
        #[cfg(not(windows))]
        {
            let _ = req;
            Err(crate::RouteGuardError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
pub mod client {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    use super::{IpcRequest, IpcResponse, PIPE_NAME};
    use crate::RouteGuardError;

    pub async fn call(req: IpcRequest) -> crate::Result<IpcResponse> {
        let mut client = ClientOptions::new()
            .open(PIPE_NAME)
            .map_err(|e| RouteGuardError::Ipc(format!("pipe connect: {e}")))?;

        let payload = serde_json::to_vec(&req)?;
        let len = (payload.len() as u32).to_le_bytes();
        client.write_all(&len).await?;
        client.write_all(&payload).await?;

        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await?;
        let resp_len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; resp_len];
        client.read_exact(&mut buf).await?;
        serde_json::from_slice(&buf).map_err(Into::into)
    }
}

#[cfg(windows)]
pub mod server {
    use std::os::windows::io::{FromRawHandle, IntoRawHandle};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::NamedPipeServer;

    use super::{IpcHandler, IpcRequest};
    use crate::pipe_security;
    use crate::RouteGuardError;

    pub struct PipeServer {
        handler: Arc<dyn IpcHandler>,
    }

    impl PipeServer {
        pub fn new(handler: Arc<dyn IpcHandler>) -> Self {
            Self { handler }
        }

        pub async fn run(self) -> crate::Result<()> {
            loop {
                if let Err(e) = self.serve_secure_instance().await {
                    tracing::warn!("IPC session error: {e}");
                }
            }
        }

        async fn serve_secure_instance(&self) -> crate::Result<()> {
            let raw = pipe_security::win::create_secure_pipe(super::PIPE_NAME)
                .map_err(|e| RouteGuardError::Ipc(format!("secure pipe create: {e}")))?;

            pipe_security::win::connect_pipe(raw)
                .map_err(|e| RouteGuardError::Ipc(format!("secure pipe connect: {e}")))?;

            let std_pipe = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
            let server = unsafe { NamedPipeServer::from_raw_handle(std_pipe.into_raw_handle())? };

            Self::serve_one(server, self.handler.clone(), true).await
        }

        async fn serve_one(
            mut server: NamedPipeServer,
            handler: Arc<dyn IpcHandler>,
            already_connected: bool,
        ) -> crate::Result<()> {
            if !already_connected {
                server.connect().await.map_err(RouteGuardError::Io)?;
            }

            let mut len_buf = [0u8; 4];
            server.read_exact(&mut len_buf).await?;
            let req_len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; req_len];
            server.read_exact(&mut buf).await?;

            let req: IpcRequest = serde_json::from_slice(&buf)?;
            let resp = handler.handle(req).await;
            let payload = serde_json::to_vec(&resp)?;
            let len = (payload.len() as u32).to_le_bytes();
            server.write_all(&len).await?;
            server.write_all(&payload).await?;
            Ok(())
        }
    }
}
