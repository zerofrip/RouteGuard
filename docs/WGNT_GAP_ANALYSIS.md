# WireGuardNT Backend — Gap Analysis

This document summarizes what remains after implementing the native `wireguard.dll` FFI backend in `routeguard-platform/src/wgnt/`.

## Implemented (Phase 1)

| Component | Status |
|-----------|--------|
| Dynamic `wireguard.dll` load via `libloading` | Done |
| `WireGuardCreateAdapter` / `OpenAdapter` / `CloseAdapter` | Done |
| `WireGuardDeleteDriver` | Exposed on `WgntLibrary`, not called on normal shutdown |
| `WireGuardSetConfiguration` / `GetConfiguration` | Done |
| `WireGuardSetAdapterState` / `GetAdapterState` | Done |
| Statistics + `last_handshake` polling | Done |
| 6-state tunnel lifecycle | Done |
| `.conf` parser (Interface + Peer fields) | Done |
| Session-scoped route tracking | Done |
| Windows integration tests (`RG_WGNT_TEST=1`) | Done |

## Missing APIs / Incomplete Wiring

| Gap | Location | Impact |
|-----|----------|--------|
| Interface IP assignment (`Address =`) | Not applied to adapter via IP Helper | Tunnel may lack L3 address until driver sets it |
| `WireGuardSetLogger` / adapter logging | FFI resolved, not wired to `tracing` | Hard to diagnose handshake failures |
| WFP tunnel-interface permit filter | `routeguard-wfp/filters.rs` | Network lock may block tunnel traffic |
| Endpoint route via physical interface | `SessionRoutes::add_endpoint_bypass` uses tunnel if_index | Possible routing loop to WG server |
| SCM Windows Service | `routeguard-service/service.rs` | No auto-start / crash restart |
| Persistent WFP provider GUID | `routeguard-wfp` | Lock may not survive crash as designed |
| DNS hijack to port 53 | `dns.rs` listens on 5353 | Domain routing inactive for most apps |
| Auto-reconnect watchdog | orchestrator | `Reconnecting` state exists but no watchdog |
| DPAPI config encryption | core config | Plaintext `.conf` paths |
| Key generation CLI | none | No `genkey` command |
| IPv6 dual-stack route cleanup | routes.rs | Partial |
| `DeleteDriver` on service stop | optional, not default | Driver may linger |

## Stub Implementations

- `routeguard-service` SCM — console mode only
- `routeguard-gui` — placeholder binary
- `routeguard-awg` / `routeguard-phantun` — traits only
- Non-Windows platform — `UnsupportedPlatform` (expected)

## Windows-Only Blockers

- Administrator elevation required (adapter + WFP)
- Signed `wireguard.dll` must ship in `wireguard-deps/`
- Integration tests require native Windows (not WSL)
- Co-existence with WireGuard for Windows if adapter names collide

## Security Concerns

- Plaintext `.conf` with private keys on disk
- IPC named pipe without ACL hardening (`\\.\pipe\RouteGuard`)
- No integrity check on `wireguard.dll` before load
- Kill switch block-all can lock out remote admin if misconfigured
- Elevated service — IPC must validate all inputs

## Recommended Phase 2 Roadmap

1. **Interface addressing** — assign `Address` via `CreateUnicastIpAddressEntry` / wireguard-nt adapter.c patterns
2. **Endpoint physical route** — `GetBestRoute2` for server IP bypass before tunnel default route
3. **WFP tunnel permit** + persistent provider GUID
4. **SCM service** + startup `teardown_orphan_adapter` recovery
5. **Auto-reconnect** watchdog using `Reconnecting` state
6. **DNS port 53** redirect + system resolver integration
7. **WFP callout driver** for true per-app split tunnel
8. **Phantun supervisor** above wgnt layer
9. **AWG decorator** above wgnt layer (packet transforms, not replacement)

## Architecture Rule

All future transport backends (AWG, Phantun, LWO) **must integrate above** `WireGuardNtBackend` / `wgnt` — they decorate or wrap the canonical tunnel, they do not replace direct `wireguard.dll` FFI.
