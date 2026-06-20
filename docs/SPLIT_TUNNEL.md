# Application Split Tunneling

RouteGuard Phase 2 implements per-application split tunneling using user-mode WFP filters and dual-default route tables — no kernel callout driver required for the primary **FullTunnel + Exclude** mode.

## Modes

| Mode | Default path | App rules |
|------|--------------|-----------|
| `full_tunnel` | VPN | `exclude` → direct (e.g. Steam) |
| `split_include` | Direct | `include` → VPN (best-effort; see limitations) |

## Example

```bash
# Default: all apps use VPN
routeguard-cli connect

# Steam bypasses VPN
routeguard-cli rules add-app "C:\Program Files (x86)\Steam\steam.exe" --mode exclude

# List rules + compiled policy
routeguard-cli rules list

# Remove rule (no tunnel restart)
routeguard-cli rules remove-app "C:\Program Files (x86)\Steam\steam.exe"
```

Chrome and OBS use the VPN by default (no rule needed). Steam uses `--mode exclude` for direct routing.

## Architecture

1. CLI → IPC `routing.add_app` / `routing.remove_app`
2. Service updates `config.toml`, reloads `RoutingEngine`
3. `AppSplitPolicyCompiler` builds `PolicySnapshot` with `bypass_apps` / `tunnel_apps`
4. `SessionRoutes` installs dual-default routes (physical metric 1, tunnel metric 100)
5. `routeguard-wfp` installs app-scoped WFP filters
6. State persisted to `%ProgramData%\RouteGuard\app_rules_state.json`

## WFP filters (FullTunnel + Exclude)

| Filter | Purpose |
|--------|---------|
| `RG_SPLIT_PERMIT_EXCL_*` | Permit excluded apps on direct path |
| `RG_SPLIT_BLOCK_TUN_EXCL_*` | Block excluded apps from using tunnel |
| `RG_SPLIT_PERMIT_TUN` | Allow tunnel interface traffic |

## Route table

- `0.0.0.0/0` → physical interface, metric **1**
- `0.0.0.0/0` → tunnel interface, metric **100**
- IP bypass CIDRs → physical interface
- WG AllowedIPs / endpoint bypass unchanged (WireGuardNT backend)

## Runtime updates

Rule changes call `apply_split_policy()` without tunnel disconnect/reconnect. On failure, config and filters roll back to the previous state.

## Limitations

- **SplitInclude** mode compiles filters but may not reliably redirect all traffic without the Phase 4 WFP callout driver (`drivers/routeguard-callout/`).
- App rules match executable paths only (no package family / SID).
- Administrator elevation required for WFP and route table changes.
- Paths must exist and end with `.exe` when adding rules.

## Testing

```bash
# Linux CI: unit tests in routeguard-routing, routeguard-wfp, routeguard-platform

# Windows (admin):
set RG_SPLIT_TEST=1
cargo test -p routeguard-platform --test split_tunnel_integration -- --ignored
```

See [SPLIT_TUNNEL_SECURITY.md](SPLIT_TUNNEL_SECURITY.md) for the threat model.
