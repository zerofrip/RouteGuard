//! Windows integration tests for native WireGuardNT backend.
//!
//! Run with administrator privileges:
//!   set RG_WGNT_TEST=1
//!   set RG_WGNT_DLL=C:\path\to\wireguard.dll
//!   cargo test -p routeguard-platform --test wgnt_integration -- --ignored --nocapture

#![cfg(windows)]

use std::path::PathBuf;
use std::time::Duration;

use routeguard_platform::wgnt::{
    parse_conf_text, query_stats, serialize_interface, wait_for_handshake, AdapterHandle,
    WgntLibrary, WIREGUARD_ADAPTER_STATE,
};
use routeguard_platform::{RouteTableManager, SessionRoutes};

fn dll_path() -> PathBuf {
    std::env::var("RG_WGNT_DLL")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../wireguard-deps/wireguard.dll")
        })
}

fn should_run() -> bool {
    std::env::var("RG_WGNT_TEST").ok().as_deref() == Some("1")
}

fn skip_if_not_enabled() {
    if !should_run() {
        eprintln!("skipping: set RG_WGNT_TEST=1 to run WireGuardNT integration tests");
    }
}

#[test]
#[ignore]
fn test_dll_load_missing() {
    skip_if_not_enabled();
    let err = WgntLibrary::load("nonexistent-wireguard.dll").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not found") || msg.contains("DllNotFound"));
}

#[test]
#[ignore]
fn test_dll_load_ok() {
    skip_if_not_enabled();
    let lib = WgntLibrary::load(dll_path()).expect("load wireguard.dll");
    let ver = lib.driver_version().expect("driver version");
    assert!(ver > 0, "driver version should be non-zero");
}

#[test]
#[ignore]
fn test_adapter_create_open_close() {
    skip_if_not_enabled();
    let lib = WgntLibrary::load(dll_path()).unwrap();
    let name = format!("RouteGuardTest_{}", std::process::id());

    let (mut adapter, created) = AdapterHandle::open_or_create(lib.clone(), &name).unwrap();
    assert!(created);

    adapter.close();
    assert!(lib.open_adapter(&name).is_err());

    let (mut adapter2, created2) = AdapterHandle::open_or_create(lib, &name).unwrap();
    assert!(created2);
    adapter2.close();
}

#[test]
#[ignore]
fn test_set_configuration() {
    skip_if_not_enabled();
    let lib = WgntLibrary::load(dll_path()).unwrap();
    let name = format!("RouteGuardCfg_{}", std::process::id());
    let (adapter, _created) = AdapterHandle::open_or_create(lib, &name).unwrap();

    let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let conf = parse_conf_text(&format!(
        r#"
[Interface]
PrivateKey = {key}
Address = 10.66.66.2/32

[Peer]
PublicKey = {key}
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
"#
    ))
    .unwrap();

    let blob = serialize_interface(&conf).unwrap();
    adapter.set_configuration(&blob).expect("set configuration");

    let stats = query_stats(&adapter).expect("query stats");
    assert_eq!(stats.peers.len(), 1);
}

#[test]
#[ignore]
fn test_adapter_state() {
    skip_if_not_enabled();
    let lib = WgntLibrary::load(dll_path()).unwrap();
    let name = format!("RouteGuardState_{}", std::process::id());
    let (adapter, _created) = AdapterHandle::open_or_create(lib, &name).unwrap();

    adapter
        .set_adapter_state(WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_UP)
        .unwrap();
    assert!(matches!(
        adapter.get_adapter_state().unwrap(),
        WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_UP
    ));

    adapter
        .set_adapter_state(WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_DOWN)
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn test_handshake_detection() {
    skip_if_not_enabled();
    let conf_path = std::env::var("RG_WG_TEST_CONF").expect("RG_WG_TEST_CONF required");
    let conf_text = std::fs::read_to_string(&conf_path).unwrap();
    let parsed = parse_conf_text(&conf_text).unwrap();
    let blob = serialize_interface(&parsed).unwrap();

    let lib = WgntLibrary::load(dll_path()).unwrap();
    let name = format!("RouteGuardHS_{}", std::process::id());
    let (adapter, _created) = AdapterHandle::open_or_create(lib, &name).unwrap();

    adapter.set_configuration(&blob).unwrap();
    adapter
        .set_adapter_state(WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_UP)
        .unwrap();

    let stats = wait_for_handshake(&adapter, Duration::from_secs(30))
        .await
        .expect("handshake");
    assert!(stats.handshake_complete());
}

#[test]
#[ignore]
fn test_route_install_remove() {
    skip_if_not_enabled();
    use ipnet::IpNet;

    let table = RouteTableManager::new();
    let mut session = SessionRoutes::new();
    let cidr: IpNet = "10.66.66.0/24".parse().unwrap();

    session.add_bypass(&table, cidr, 1).expect("install route");
    session.clear(&table).expect("remove routes");
}
