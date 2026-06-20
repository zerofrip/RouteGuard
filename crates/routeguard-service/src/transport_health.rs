//! Periodic transport health checks for LWO and Phantun relays.

use std::sync::Arc;
use std::time::Duration;

use routeguard_core::events::TunnelEvent;
use routeguard_core::transport::{TransportHealth, TransportKind};

use crate::connect_session::ActiveConnectSession;
use crate::handler::ServiceContext;
use crate::transport_selector::TransportChoice;

const MAX_RECOVERY_ATTEMPTS: u32 = 3;
const BACKOFF_SECS: [u64; 3] = [5, 10, 15];

pub fn spawn_transport_health_monitor(ctx: Arc<ServiceContext>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut recovery_attempts: u32 = 0;

        loop {
            interval.tick().await;

            let Some(active) = ctx.active_session.active() else {
                recovery_attempts = 0;
                continue;
            };

            if matches!(active.transport_choice, TransportChoice::DirectUdp) {
                recovery_attempts = 0;
                continue;
            }

            let health = ctx
                .transport_selector
                .health_async(active.transport_choice, &active.transport_session)
                .await;

            if health == TransportHealth::Healthy {
                recovery_attempts = 0;
                continue;
            }

            recovery_attempts += 1;
            if recovery_attempts > MAX_RECOVERY_ATTEMPTS {
                ctx.orchestrator
                    .events()
                    .publish(TunnelEvent::TransportFailed {
                        name: active.tunnel_name.clone(),
                        kind: active.transport_session.kind,
                        reason: "transport health check failed after max recovery attempts".into(),
                        recoverable: false,
                    });
                recovery_attempts = 0;
                continue;
            }

            ctx.orchestrator
                .events()
                .publish(TunnelEvent::TransportRecovering {
                    name: active.tunnel_name.clone(),
                    kind: active.transport_session.kind,
                    attempt: recovery_attempts,
                    max_attempts: MAX_RECOVERY_ATTEMPTS,
                });

            let backoff = BACKOFF_SECS
                .get((recovery_attempts - 1) as usize)
                .copied()
                .unwrap_or(15);
            tokio::time::sleep(Duration::from_secs(backoff)).await;

            if ctx.active_session.active().is_none() {
                recovery_attempts = 0;
                continue;
            }

            match restart_transport(&ctx, &active).await {
                Ok(new_active) => {
                    ctx.observability.record_recovery_attempt(true, None);
                    ctx.orchestrator
                        .events()
                        .publish(TunnelEvent::TransportRecoveryResult {
                            kind: active.transport_session.kind,
                            attempt: recovery_attempts,
                            success: true,
                            reason: None,
                        });
                    let connected = TunnelEvent::TransportConnected {
                        name: new_active.tunnel_name.clone(),
                        kind: new_active.transport_session.kind,
                        local_endpoint: new_active.transport_session.wireguard_endpoint.to_string(),
                        remote_transport: new_active
                            .transport_session
                            .remote_transport
                            .map(|a| a.to_string()),
                        protocol_version: if new_active.transport_session.kind == TransportKind::Lwo
                        {
                            Some(new_active.transport_session.protocol_version)
                        } else {
                            None
                        },
                        wire_format: new_active.transport_session.wire_format.clone(),
                    };
                    ctx.orchestrator.events().publish(connected);
                    ctx.active_session.set(new_active);
                    let _ = ctx.apply_full_policy().await;
                    recovery_attempts = 0;
                }
                Err(reason) => {
                    ctx.observability
                        .record_recovery_attempt(false, Some(reason.clone()));
                    ctx.orchestrator
                        .events()
                        .publish(TunnelEvent::TransportRecoveryResult {
                            kind: active.transport_session.kind,
                            attempt: recovery_attempts,
                            success: false,
                            reason: Some(reason.clone()),
                        });
                    ctx.orchestrator
                        .events()
                        .publish(TunnelEvent::TransportFailed {
                            name: active.tunnel_name.clone(),
                            kind: active.transport_session.kind,
                            reason,
                            recoverable: recovery_attempts < MAX_RECOVERY_ATTEMPTS,
                        });
                }
            }
        }
    });
}

async fn restart_transport(
    ctx: &ServiceContext,
    active: &ActiveConnectSession,
) -> Result<ActiveConnectSession, String> {
    let conf_text = tokio::fs::read_to_string(&active.source_config_path)
        .await
        .map_err(|e| format!("read source conf: {e}"))?;

    let prepared = ctx
        .transport_selector
        .restart(
            active.transport_choice,
            &active.merged_transport,
            active.peer_endpoint,
            &active.tunnel_name,
            &conf_text,
            &active.resolved_transport,
            &active.transport_session,
        )
        .await
        .map_err(|e| e.to_string())?;

    ActiveConnectSession::from_prepared(
        prepared,
        active.transport_choice,
        active.source_config_path.clone(),
    )
    .ok_or_else(|| "transport restart produced no session".into())
}
