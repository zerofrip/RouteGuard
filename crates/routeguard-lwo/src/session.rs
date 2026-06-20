//! Running LWO relay registry.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::relay::LwoRelay;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

static RUNNING: Mutex<Option<HashMap<u64, LwoRelay>>> = Mutex::new(None);

fn map() -> std::sync::MutexGuard<'static, Option<HashMap<u64, LwoRelay>>> {
    let mut guard = RUNNING.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

pub fn insert(relay: LwoRelay) -> (u64, std::net::SocketAddr) {
    let local = relay.local;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    map().as_mut().unwrap().insert(id, relay);
    (id, local)
}

pub fn remove(id: u64) {
    if let Some(m) = map().as_mut() {
        m.remove(&id);
    }
}

pub fn is_healthy(id: u64) -> bool {
    map()
        .as_ref()
        .and_then(|m| m.get(&id))
        .map(|r| r.is_healthy())
        .unwrap_or(false)
}
