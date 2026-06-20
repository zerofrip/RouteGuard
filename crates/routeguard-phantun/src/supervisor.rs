//! Phantun process supervisor.

use std::net::SocketAddr;
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::atomic::AtomicU64;

#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::sync::atomic::Ordering;
#[cfg(windows)]
use std::sync::Mutex;

use routeguard_core::error::{Result, RouteGuardError};

#[cfg(windows)]
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(windows)]
struct RunningPhantun {
    child: std::process::Child,
    local: SocketAddr,
    remote: SocketAddr,
}

#[cfg(windows)]
static RUNNING: Mutex<Option<HashMap<u64, RunningPhantun>>> = Mutex::new(None);

#[cfg(windows)]
fn running_map() -> std::sync::MutexGuard<'static, Option<HashMap<u64, RunningPhantun>>> {
    let mut guard = RUNNING.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

pub fn resolve_phantun_binary() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("phantun_client.exe")))
        .unwrap_or_else(|| PathBuf::from("phantun_client.exe"))
}

pub fn probe_phantun_binary() -> bool {
    resolve_phantun_binary().is_file()
}

pub fn pick_local_listen(cfg_local: Option<&str>) -> Result<SocketAddr> {
    if let Some(s) = cfg_local {
        let addr: SocketAddr = s
            .parse()
            .map_err(|e| RouteGuardError::Config(format!("invalid local_listen: {e}")))?;
        if addr.port() != 0 {
            return Ok(addr);
        }
        return bind_ephemeral(addr.ip());
    }
    bind_ephemeral("127.0.0.1".parse().unwrap())
}

fn bind_ephemeral(ip: std::net::IpAddr) -> Result<SocketAddr> {
    let sock = std::net::UdpSocket::bind((ip, 0))
        .map_err(|e| RouteGuardError::Platform(format!("bind local UDP: {e}")))?;
    sock.local_addr()
        .map_err(|e| RouteGuardError::Platform(format!("local_addr: {e}")))
}

#[cfg(windows)]
pub fn spawn_phantun(local: SocketAddr, remote: SocketAddr) -> Result<(u64, SocketAddr)> {
    let binary = resolve_phantun_binary();
    if !binary.is_file() {
        return Err(RouteGuardError::Platform(
            "phantun_client.exe not found".into(),
        ));
    }

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let child = std::process::Command::new(&binary)
        .arg("--local")
        .arg(local.to_string())
        .arg("--remote")
        .arg(remote.to_string())
        .spawn()
        .map_err(|e| RouteGuardError::Platform(format!("spawn phantun: {e}")))?;

    running_map().as_mut().unwrap().insert(
        id,
        RunningPhantun {
            child,
            local,
            remote,
        },
    );

    Ok((id, local))
}

#[cfg(not(windows))]
pub fn spawn_phantun(_local: SocketAddr, _remote: SocketAddr) -> Result<(u64, SocketAddr)> {
    Err(RouteGuardError::UnsupportedPlatform)
}

#[cfg(windows)]
pub fn stop_phantun(id: u64) -> Result<()> {
    let mut guard = running_map();
    if let Some(map) = guard.as_mut() {
        if let Some(mut entry) = map.remove(&id) {
            let _ = entry.child.kill();
            let _ = entry.child.wait();
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn stop_phantun(_id: u64) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn is_running(id: u64) -> bool {
    let mut guard = running_map();
    if let Some(map) = guard.as_mut() {
        if let Some(entry) = map.get_mut(&id) {
            match entry.child.try_wait() {
                Ok(None) => return true,
                Ok(Some(_)) => {
                    map.remove(&id);
                    return false;
                }
                Err(_) => return false,
            }
        }
    }
    false
}

#[cfg(not(windows))]
pub fn is_running(_id: u64) -> bool {
    false
}
