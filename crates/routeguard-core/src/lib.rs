//! RouteGuard core — config, errors, events, tunnel traits, IPC, orchestrator.

pub mod backend;
pub mod config;
pub mod error;
pub mod events;
pub mod ipc;
pub mod observability;
pub mod orchestrator;
pub mod pipe_security;
pub mod policy;
pub mod profile;
pub mod transport;
pub mod tunnel;

pub use backend::{BackendKind, ProfileKind, TunnelBackendPreference};
pub use config::{AppConfig, NetworkLockConfig, RoutingConfig, TunnelConfig};
pub use error::{Result, RouteGuardError};
pub use events::{EventRecord, EventStore, NetworkLockEvent, RoutingEvent, TunnelEvent};
pub use ipc::{IpcClient, IpcRequest, IpcResponse, IpcServer, PIPE_NAME};
pub use observability::{
    compute_health, list_metrics, obs_now_iso, CapabilitiesObs, DiagnosticsExportParams,
    DiagnosticsExportResult, DnsObs, HealthComponent, HealthReport, HealthStatus,
    KNOWN_METRICS, MetricDescriptor, MetricSeries, MetricSeriesPoint, MetricsListResult, NetworkLockObs,
    ObservabilityFeatures, ObservabilityHistoryParams, ObservabilityHistoryResult,
    ObservabilitySnapshot, ObservabilitySnapshotParams, RoutingObs, ServiceObs, TransportObs,
    TunnelObs, OBSERVABILITY_SCHEMA_VERSION,
};
pub use orchestrator::TunnelOrchestrator;
pub use policy::{AppFilterEntry, PolicySnapshot, SessionState};
pub use profile::{
    ProfileExportParams, ProfileImportParams, ProfileIndex, ProfileValidateParams,
    ProfileValidateResult, ProfileValidationIssue, ResolvedBackend, TunnelProfile,
};
pub use transport::{
    LwoTransportConfig, PhantunTransportConfig, PolicyTransportEndpoints, PreparedConnect,
    ResolvedTransport, TransportBackend, TransportCapabilities, TransportHealth, TransportKind,
    TransportPermitRule, TransportPreference, TransportProbeResult, TransportProtocol,
    TransportSession, TransportValidateResult, TransportValidationIssue, TunnelTransportConfig,
};
pub use tunnel::{TunnelBackend, TunnelHandle, TunnelLifecycle, TunnelStats, TunnelStatus};
