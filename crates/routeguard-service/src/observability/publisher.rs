//! 1 s stats publisher → events + metrics store.

use std::sync::Arc;

use routeguard_core::events::TunnelEvent;
use routeguard_core::observability::HealthStatus;
use routeguard_core::transport::TransportKind;

use crate::handler::ServiceContext;
use crate::observability::collectors::{collect_snapshot, transport_health_str, update_rates};
use crate::transport_selector::TransportChoice;

const HANDSHAKE_THRESHOLDS: &[u64] = &[30, 120, 300];

pub fn spawn_stats_publisher(ctx: Arc<ServiceContext>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;

            let handle = ctx.orchestrator.active_handle().await;
            let Some(h) = handle else {
                continue;
            };

            let choice = ctx.selector.choice_for(h.backend);
            let Ok(stats) = ctx.selector.stats(choice, &h) else {
                continue;
            };

            update_rates(&ctx.observability, &stats);

            ctx.orchestrator.events().publish(TunnelEvent::Stats {
                name: h.name.clone(),
                rx_bytes: stats.rx_bytes,
                tx_bytes: stats.tx_bytes,
                rx_rate_bps: *ctx.observability.last_rx_rate.lock().unwrap() * 8,
                tx_rate_bps: *ctx.observability.last_tx_rate.lock().unwrap() * 8,
                peer_count: stats.peer_count,
            });

            if let Some(age) = stats.last_handshake_secs_ago {
                let mut last = ctx.observability.last_handshake_threshold.lock().unwrap();
                for &t in HANDSHAKE_THRESHOLDS {
                    if age >= t {
                        if last.map(|l| l < t).unwrap_or(true) {
                            ctx.orchestrator
                                .events()
                                .publish(TunnelEvent::HandshakeThreshold {
                                    name: h.name.clone(),
                                    last_handshake_secs_ago: age,
                                    peer_count: stats.peer_count,
                                });
                            *last = Some(t);
                        }
                        break;
                    }
                }
                if age < 30 {
                    *last = None;
                }
            }

            if let Some(active) = ctx.active_session.active() {
                if !matches!(active.transport_choice, TransportChoice::DirectUdp) {
                    let health = ctx
                        .transport_selector
                        .health_async(active.transport_choice, &active.transport_session)
                        .await;
                    let health_str = transport_health_str(health);
                    let prev = ctx
                        .observability
                        .last_transport_kind_health
                        .lock()
                        .unwrap()
                        .clone();
                    let kind = active.transport_session.kind;
                    if prev.as_ref().map(|(_, h)| h.as_str()) != Some(health_str) {
                        ctx.observability.set_transport_health(kind, health_str);
                        ctx.orchestrator
                            .events()
                            .publish(TunnelEvent::TransportHealthChanged {
                                kind,
                                health: health_str.to_string(),
                                local_endpoint: Some(
                                    active.transport_session.wireguard_endpoint.to_string(),
                                ),
                            });
                    }
                }
            }

            let snap = collect_snapshot(&ctx, None).await;
            let score = snap.health.score;
            let prev_score = *ctx.observability.last_health_score.lock().unwrap();
            let band_changed =
                HealthStatus::from_score(score) != HealthStatus::from_score(prev_score);
            let big_delta = score.abs_diff(prev_score) >= 10;
            if band_changed || big_delta {
                ctx.orchestrator
                    .events()
                    .publish(TunnelEvent::ObservabilityHealthChanged {
                        score,
                        status: format!("{:?}", snap.health.status).to_lowercase(),
                        previous_score: prev_score,
                    });
                *ctx.observability.last_health_score.lock().unwrap() = score;
            }
        }
    });
}

pub fn spawn_history_persist(ctx: Arc<ServiceContext>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        let path = crate::observability::store::metrics_dir().join("rollups.jsonl");
        loop {
            interval.tick().await;
            ctx.observability.metrics.persist_rollups(&path);
        }
    });
}
