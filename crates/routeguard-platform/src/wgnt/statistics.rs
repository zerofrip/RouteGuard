//! Query adapter/peer statistics via WireGuardGetConfiguration.

#[cfg(windows)]
mod imp {
    use std::time::SystemTime;

    use super::super::adapter::AdapterHandle;
    use super::super::bindings::{
        wireguard_epoch_to_system_time, WIREGUARD_INTERFACE, WIREGUARD_PEER,
    };
    use super::super::error::{WgntError, WgntResult};

    #[derive(Debug, Clone, Default)]
    pub struct PeerStats {
        pub rx_bytes: u64,
        pub tx_bytes: u64,
        pub last_handshake: Option<SystemTime>,
    }

    #[derive(Debug, Clone, Default)]
    pub struct InterfaceStats {
        pub peers: Vec<PeerStats>,
    }

    impl InterfaceStats {
        pub fn totals(&self) -> (u64, u64) {
            self.peers
                .iter()
                .fold((0, 0), |(rx, tx), p| (rx + p.rx_bytes, tx + p.tx_bytes))
        }

        pub fn handshake_complete(&self) -> bool {
            self.peers.iter().any(|p| p.last_handshake.is_some())
        }
    }

    pub fn query_stats(adapter: &AdapterHandle) -> WgntResult<InterfaceStats> {
        let mut buf = vec![0u8; 4096];
        let needed = adapter
            .library
            .get_configuration(adapter.raw(), &mut buf)
            .or_else(|e| match e {
                WgntError::Api { code, .. }
                    if code == windows_sys::Win32::Foundation::ERROR_MORE_DATA =>
                {
                    Ok(8192)
                }
                other => Err(other),
            })?;

        if needed > buf.len() {
            buf.resize(needed, 0);
        }

        let used = adapter.library.get_configuration(adapter.raw(), &mut buf)?;
        parse_config_buffer(&buf[..used])
    }

    fn parse_config_buffer(bytes: &[u8]) -> WgntResult<InterfaceStats> {
        if bytes.len() < std::mem::size_of::<WIREGUARD_INTERFACE>() {
            return Ok(InterfaceStats::default());
        }

        unsafe {
            let iface = &*(bytes.as_ptr() as *const WIREGUARD_INTERFACE);
            let peer_count = iface.PeersCount as usize;
            let mut offset = std::mem::size_of::<WIREGUARD_INTERFACE>();
            let mut peers = Vec::with_capacity(peer_count);

            for _ in 0..peer_count {
                if offset + std::mem::size_of::<WIREGUARD_PEER>() > bytes.len() {
                    break;
                }
                let peer = &*(bytes.as_ptr().add(offset) as *const WIREGUARD_PEER);
                let allowed_count = peer.AllowedIPsCount as usize;
                let allowed_size = allowed_count
                    * std::mem::size_of::<super::super::bindings::WIREGUARD_ALLOWED_IP>();
                offset += std::mem::size_of::<WIREGUARD_PEER>() + allowed_size;

                peers.push(PeerStats {
                    rx_bytes: peer.RxBytes,
                    tx_bytes: peer.TxBytes,
                    last_handshake: wireguard_epoch_to_system_time(peer.LastHandshake),
                });
            }

            Ok(InterfaceStats { peers })
        }
    }

    pub async fn wait_for_handshake(
        adapter: &AdapterHandle,
        timeout: std::time::Duration,
    ) -> WgntResult<InterfaceStats> {
        let start = std::time::Instant::now();
        loop {
            let stats = query_stats(adapter)?;
            if stats.handshake_complete() {
                return Ok(stats);
            }
            if start.elapsed() >= timeout {
                return Err(WgntError::HandshakeTimeout {
                    secs: timeout.as_secs(),
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
}

#[cfg(windows)]
pub use imp::{query_stats, wait_for_handshake, InterfaceStats, PeerStats};
