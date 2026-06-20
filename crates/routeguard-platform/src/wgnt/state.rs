//! Tunnel lifecycle state helpers.

use routeguard_core::tunnel::TunnelLifecycle;

pub fn can_connect(state: TunnelLifecycle) -> bool {
    matches!(
        state,
        TunnelLifecycle::Disconnected | TunnelLifecycle::Error
    )
}

pub fn can_disconnect(state: TunnelLifecycle) -> bool {
    matches!(
        state,
        TunnelLifecycle::Connected | TunnelLifecycle::Connecting | TunnelLifecycle::Reconnecting
    )
}

pub fn transition_connect_start() -> TunnelLifecycle {
    TunnelLifecycle::Connecting
}

pub fn transition_connected() -> TunnelLifecycle {
    TunnelLifecycle::Connected
}

pub fn transition_disconnect_start() -> TunnelLifecycle {
    TunnelLifecycle::Disconnecting
}

pub fn transition_disconnected() -> TunnelLifecycle {
    TunnelLifecycle::Disconnected
}

pub fn transition_error() -> TunnelLifecycle {
    TunnelLifecycle::Error
}

pub fn transition_reconnecting() -> TunnelLifecycle {
    TunnelLifecycle::Reconnecting
}

pub fn lifecycle_to_status(state: TunnelLifecycle) -> routeguard_core::tunnel::TunnelStatus {
    use routeguard_core::tunnel::TunnelStatus;
    match state {
        TunnelLifecycle::Disconnected => TunnelStatus::Disconnected,
        TunnelLifecycle::Connecting => TunnelStatus::Connecting,
        TunnelLifecycle::Connected => TunnelStatus::Connected,
        TunnelLifecycle::Reconnecting => TunnelStatus::Reconnecting,
        TunnelLifecycle::Disconnecting => TunnelStatus::Disconnecting,
        TunnelLifecycle::Error => TunnelStatus::Error,
    }
}
