//! Phantun UDP-over-TCP transport for RouteGuard.

mod backend;
mod supervisor;

pub use backend::PhantunBackend;
pub use supervisor::{probe_phantun_binary, resolve_phantun_binary};

/// Local UDP endpoint WireGuard binds to; remote Phantun TCP server.
#[derive(Debug, Clone)]
pub struct TransportEndpoint {
    pub listen: std::net::SocketAddr,
    pub remote_tcp: std::net::SocketAddr,
}

/// Opaque handle to a running Phantun process/supervisor.
#[derive(Debug, Clone)]
pub struct TransportHandle {
    pub id: u64,
}

pub type PhantunResult<T> = Result<T, PhantunError>;

#[derive(Debug, thiserror::Error)]
pub enum PhantunError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("not running")]
    NotRunning,
}

#[cfg(test)]
mod tests {
    use routeguard_core::transport::TransportBackend;

    use super::*;

    #[test]
    fn recommended_mtu_ipv4() {
        let t = PhantunBackend::new();
        assert_eq!(t.recommended_mtu(1500), 1428);
    }
}
