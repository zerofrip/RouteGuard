//! In-process UDP relay with Mullvad-compatible obfuscation.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::keys::LwoKeys;
use crate::wire::{deobfuscate, obfuscate};

const MAX_UDP_SIZE: usize = u16::MAX as usize;

pub struct LwoRelay {
    cancel: CancellationToken,
    send: JoinHandle<()>,
    recv: JoinHandle<()>,
    pub local: SocketAddr,
    #[allow(dead_code)]
    pub remote: SocketAddr,
}

impl LwoRelay {
    pub async fn start(
        keys: &LwoKeys,
        remote: SocketAddr,
        local_listen: Option<SocketAddr>,
    ) -> std::io::Result<Self> {
        let client_socket = Arc::new(
            UdpSocket::bind(local_listen.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap())).await?,
        );
        let local = client_socket.local_addr()?;

        let remote_socket = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?);
        remote_socket.connect(remote).await?;

        let client_addr = client_socket.local_addr()?;
        client_socket.connect(client_addr).await?;

        let cancel = CancellationToken::new();

        let tx_key = keys.server_public;
        let rx_key = keys.client_public;

        let send_cancel = cancel.clone();
        let recv_cancel = cancel.clone();

        let rx_sock = client_socket.clone();
        let tx_sock = remote_socket.clone();
        let send = tokio::spawn(async move {
            run_loop(true, tx_key, rx_sock, tx_sock, send_cancel).await;
        });

        let rx_sock = remote_socket.clone();
        let tx_sock = client_socket.clone();
        let recv = tokio::spawn(async move {
            run_loop(false, rx_key, rx_sock, tx_sock, recv_cancel).await;
        });

        Ok(Self {
            cancel,
            send,
            recv,
            local,
            remote,
        })
    }

    pub fn is_healthy(&self) -> bool {
        !self.send.is_finished() && !self.recv.is_finished()
    }

    #[allow(dead_code)]
    pub fn stop(self) {
        self.cancel.cancel();
    }
}

impl Drop for LwoRelay {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.send.abort();
        self.recv.abort();
    }
}

async fn run_loop(
    sending: bool,
    key: [u8; 32],
    read_socket: Arc<UdpSocket>,
    write_socket: Arc<UdpSocket>,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; MAX_UDP_SIZE];

    loop {
        if cancel.is_cancelled() {
            return;
        }

        let read_n = tokio::select! {
            _ = cancel.cancelled() => return,
            r = read_socket.recv(&mut buf) => match r {
                Ok(n) => n,
                Err(_) => return,
            },
        };

        if sending {
            obfuscate(&mut rand::thread_rng(), &mut buf[..read_n], &key);
        } else {
            deobfuscate(&mut buf[..read_n], &key);
        }

        if write_socket.send(&buf[..read_n]).await.is_err() {
            return;
        }
    }
}
