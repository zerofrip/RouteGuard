//! Windows SCM integration for routeguard-service.

use std::ffi::OsString;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use routeguard_core::Result;

use crate::handler::ServiceContext;

static SERVICE_CTX: OnceLock<Arc<ServiceContext>> = OnceLock::new();

pub fn set_service_context(ctx: Arc<ServiceContext>) {
    let _ = SERVICE_CTX.set(ctx);
}

#[cfg(windows)]
pub fn run_as_service(ctx: Arc<ServiceContext>) -> Result<()> {
    const SERVICE_NAME: &str = "RouteGuard";
    set_service_context(ctx);
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| {
        routeguard_core::RouteGuardError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("service dispatcher: {e}"),
        ))
    })
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("RouteGuard service failed: {e}");
    }
}

#[cfg(windows)]
fn run_service() -> Result<()> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    const SERVICE_NAME: &str = "RouteGuard";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.try_send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle =
        service_control_handler::register(SERVICE_NAME, event_handler).map_err(|e| {
            routeguard_core::RouteGuardError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("service control handler: {e}"),
            ))
        })?;

    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| {
            routeguard_core::RouteGuardError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("set service status: {e}"),
            ))
        })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("routeguard-service")
        .build()
        .map_err(|e| {
            routeguard_core::RouteGuardError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("tokio runtime: {e}"),
            ))
        })?;

    let ctx = SERVICE_CTX.get().cloned().ok_or_else(|| {
        routeguard_core::RouteGuardError::InvalidState("service context not initialized".into())
    })?;

    #[cfg(windows)]
    {
        use routeguard_core::events::NetworkLockEvent;
        use serde_json::json;

        match routeguard_wfp::cleanup_stale() {
            Ok(removed) => {
                ctx.event_store.push(
                    "network_lock.recovered",
                    json!({ "staleFiltersRemoved": removed }),
                );
                ctx.orchestrator
                    .publish_network_lock(NetworkLockEvent::Recovered {
                        stale_filters_removed: removed,
                    });
            }
            Err(e) => tracing::warn!("WFP cleanup_stale on service start: {e}"),
        }
    }

    rt.block_on(async {
        crate::transport_health::spawn_transport_health_monitor(ctx.clone());
        crate::observability::spawn_stats_publisher(ctx.clone());
        crate::observability::spawn_history_persist(ctx.clone());

        let handler = ctx.clone();
        let ipc_task = tokio::spawn(async move {
            let server = routeguard_core::ipc::server::PipeServer::new(handler);
            if let Err(e) = server.run().await {
                tracing::error!("IPC server error: {e}");
            }
        });

        shutdown_rx.recv().await;
        ipc_task.abort();

        status_handle
            .set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .ok();

        Ok(())
    })
}

#[cfg(not(windows))]
pub async fn run_as_service(_ctx: Arc<ServiceContext>) -> routeguard_core::Result<()> {
    Err(routeguard_core::RouteGuardError::UnsupportedPlatform)
}
