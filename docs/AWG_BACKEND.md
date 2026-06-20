# AWG Backend (Phase 7)

Amnezia WireGuard (AWG) integration as a first-class tunnel backend alongside WireGuardNT.

## Overview

```
Profile (.conf with Jc/H1/…) → TunnelBackendSelector
  → auto: AWG if params + tunnel.dll present, else WGNT
  → AwgBackend (tunnel.dll) or WireGuardNtBackend (wireguard.dll)
  → TunnelHandle { backend, if_index, if_luid }
  → NL + Split + Domain routing (unchanged)
```

## Configuration

```toml
[tunnel]
name = "awg-vpn"
config_path = "C:\\ProgramData\\RouteGuard\\profiles\\awg-vpn.conf"
backend = "auto"       # auto | wireguard_nt | awg
require_awg = false    # fail connect if AWG DLL missing when profile has AWG keys
mtu = 1280
```

## AWG interface parameters

| Key | Field | Notes |
|-----|-------|-------|
| Jc | junk packet count | Requires Jmin/Jmax when > 0 |
| Jmin | min junk size | ≤ Jmax |
| Jmax | max junk size | |
| S1 | init junk size | |
| S2 | response junk size | |
| H1–H4 | magic header specs | `N` or `N-M` (u32 range) |

## Backend selection

| backend | AWG keys | tunnel.dll | Result |
|---------|----------|------------|--------|
| wireguard_nt | any | any | WGNT |
| awg | any | yes | AWG |
| awg | any | no | Error |
| auto | none | any | WGNT |
| auto | yes | yes | AWG |
| auto | yes | no | WGNT + `tunnel.backend_fallback` event |

## DLL layout

Place amneziawg embeddable build output beside RouteGuard:

```
RouteGuard/
  wireguard.dll   # WireGuardNT (standard profiles)
  tunnel.dll      # AmneziaWG (AWG profiles)
```

See [awg-deps/README.md](../awg-deps/README.md).

## IPC

| Method | Purpose |
|--------|---------|
| `tunnel.profile.import` | Import `.conf` with AWG validation |
| `tunnel.profile.export` | Export full/sanitized |
| `tunnel.profile.validate` | Parse + validate without save |
| `tunnel.profile.list/get/delete` | Profile vault CRUD |
| `tunnel.connect` | `{ profileName?, config_path?, name? }` |
| `tunnel.status` | Includes `backend`, `awgActive`, `fallbackUsed` |
| `service.capabilities` | `awg`, `awgParams[]` |

## Events

| type | When |
|------|------|
| `tunnel.awg.connected` | AWG backend connect complete |
| `tunnel.backend_fallback` | auto mode fell back to WGNT |
| `tunnel.profile.imported` | Profile saved to vault |
| `tunnel.connected` | Extended with `backend` field |

## Components

| Crate | Module |
|-------|--------|
| `routeguard-awg` | `params`, `validate`, `conf` |
| `routeguard-platform` | `awg::AwgBackend` |
| `routeguard-service` | `backend_selector`, `profile_store` |
| `routeguard-core` | `backend`, `profile`, extended `TunnelHandle` |

## Security

- AWG obfuscates traffic patterns; WireGuard encryption unchanged
- `require_awg` fails closed when DLL absent
- Fallback never strips AWG keys silently
- DLL loaded only from RouteGuard install directory

## Testing

- Linux CI: `cargo test -p routeguard-awg`
- Windows VM: `tests/scripts/awg_connect_matrix.ps1`
