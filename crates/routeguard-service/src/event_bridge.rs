//! Bridge orchestrator EventBus → external EventStore for `events.poll`.

use std::sync::Arc;

use routeguard_core::events::{EventStore, NetworkLockEvent, TunnelEvent};
use serde_json::json;

pub fn spawn_event_bridge(events: &routeguard_core::events::EventBus, store: Arc<EventStore>) {
    let mut rx = events.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(payload) => {
                    if let Ok(event) = serde_json::from_str::<TunnelEvent>(&payload) {
                        push_tunnel_event(&store, event);
                    } else if let Ok(event) = serde_json::from_str::<NetworkLockEvent>(&payload) {
                        push_network_lock_event(&store, event);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

fn push_network_lock_event(store: &EventStore, event: NetworkLockEvent) {
    match event {
        NetworkLockEvent::Enabled => {
            store.push("network_lock.enabled", json!({ "active": true }));
        }
        NetworkLockEvent::Disabled => {
            store.push("network_lock.disabled", json!({ "active": false }));
        }
        NetworkLockEvent::Recovered {
            stale_filters_removed,
        } => {
            store.push(
                "network_lock.recovered",
                json!({ "staleFiltersRemoved": stale_filters_removed }),
            );
        }
        NetworkLockEvent::ViolationBlocked { remote_ip } => {
            store.push(
                "network_lock.violation_blocked",
                json!({ "remoteIp": remote_ip.to_string() }),
            );
        }
    }
}

fn push_tunnel_event(store: &EventStore, event: TunnelEvent) {
    match event {
        TunnelEvent::Connecting { name } => {
            store.push("tunnel.connecting", json!({ "name": name }));
        }
        TunnelEvent::Connected {
            name,
            if_index,
            backend,
        } => {
            store.push(
                "tunnel.connected",
                json!({ "name": name, "ifIndex": if_index, "backend": backend.as_str() }),
            );
        }
        TunnelEvent::AwgConnected { name, if_index } => {
            store.push(
                "tunnel.awg.connected",
                json!({ "name": name, "ifIndex": if_index }),
            );
        }
        TunnelEvent::BackendFallback {
            name,
            requested,
            actual,
            reason,
        } => {
            store.push(
                "tunnel.backend_fallback",
                json!({
                    "name": name,
                    "requested": requested.as_str(),
                    "actual": actual.as_str(),
                    "reason": reason,
                }),
            );
        }
        TunnelEvent::Disconnecting { name } => {
            store.push("tunnel.disconnecting", json!({ "name": name }));
        }
        TunnelEvent::Disconnected { name, backend } => {
            store.push(
                "tunnel.disconnected",
                json!({ "name": name, "backend": backend.as_str() }),
            );
        }
        TunnelEvent::Error { name, message } => {
            store.push("tunnel.error", json!({ "name": name, "message": message }));
        }
        TunnelEvent::Stats {
            name,
            rx_bytes,
            tx_bytes,
            rx_rate_bps,
            tx_rate_bps,
            peer_count,
        } => {
            store.push(
                "tunnel.stats",
                json!({
                    "name": name,
                    "rxBytes": rx_bytes,
                    "txBytes": tx_bytes,
                    "rxRateBps": rx_rate_bps,
                    "txRateBps": tx_rate_bps,
                    "peerCount": peer_count,
                }),
            );
        }
        TunnelEvent::SessionStateChanged { name, state } => {
            store.push(
                "tunnel.session_state",
                json!({ "name": name, "state": state }),
            );
        }
        TunnelEvent::HandshakeThreshold {
            name,
            last_handshake_secs_ago,
            peer_count,
        } => {
            store.push(
                "tunnel.handshake",
                json!({
                    "name": name,
                    "lastHandshakeSecsAgo": last_handshake_secs_ago,
                    "peerCount": peer_count,
                }),
            );
        }
        TunnelEvent::ObservabilityHealthChanged {
            score,
            status,
            previous_score,
        } => {
            store.push(
                "observability.health_changed",
                json!({
                    "score": score,
                    "status": status,
                    "previousScore": previous_score,
                }),
            );
        }
        TunnelEvent::TransportHealthChanged {
            kind,
            health,
            local_endpoint,
        } => {
            store.push(
                "transport.health_changed",
                json!({
                    "kind": kind.as_str(),
                    "health": health,
                    "localEndpoint": local_endpoint,
                }),
            );
        }
        TunnelEvent::TransportRecoveryResult {
            kind,
            attempt,
            success,
            reason,
        } => {
            store.push(
                "transport.recovery",
                json!({
                    "kind": kind.as_str(),
                    "attempt": attempt,
                    "success": success,
                    "reason": reason,
                }),
            );
        }
        TunnelEvent::DnsRedirectStats { stats } => {
            store.push("dns.redirect_stats", json!({ "stats": stats }));
        }
        TunnelEvent::ProfileImported { name, kind } => {
            store.push(
                "tunnel.profile.imported",
                json!({ "name": name, "kind": kind }),
            );
        }
        TunnelEvent::ProfileValidationFailed { name, errors } => {
            store.push(
                "tunnel.profile.validation_failed",
                json!({ "name": name, "errors": errors }),
            );
        }
        TunnelEvent::TransportStarting { name, kind } => {
            store.push(
                "transport.starting",
                json!({ "name": name, "kind": kind.as_str() }),
            );
        }
        TunnelEvent::TransportConnected {
            name,
            kind,
            local_endpoint,
            remote_transport,
            protocol_version,
            wire_format,
        } => {
            store.push(
                "transport.connected",
                json!({
                    "name": name,
                    "kind": kind.as_str(),
                    "localEndpoint": local_endpoint,
                    "remoteTransport": remote_transport,
                    "protocolVersion": protocol_version,
                    "wireFormat": wire_format,
                }),
            );
        }
        TunnelEvent::TransportFailed {
            name,
            kind,
            reason,
            recoverable,
        } => {
            store.push(
                "transport.failed",
                json!({
                    "name": name,
                    "kind": kind.as_str(),
                    "reason": reason,
                    "recoverable": recoverable,
                }),
            );
        }
        TunnelEvent::TransportFallback {
            name,
            requested,
            actual,
            reason,
        } => {
            store.push(
                "transport.fallback",
                json!({
                    "name": name,
                    "requested": requested.as_str(),
                    "actual": actual.as_str(),
                    "reason": reason,
                }),
            );
        }
        TunnelEvent::TransportDisconnected { name, kind } => {
            store.push(
                "transport.disconnected",
                json!({ "name": name, "kind": kind.as_str() }),
            );
        }
        TunnelEvent::TransportRecovering {
            name,
            kind,
            attempt,
            max_attempts,
        } => {
            store.push(
                "transport.recovering",
                json!({
                    "name": name,
                    "kind": kind.as_str(),
                    "attempt": attempt,
                    "maxAttempts": max_attempts,
                }),
            );
        }
    }
}
