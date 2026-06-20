# RouteGuard Architecture

See the project plan for full design. Summary:

## Crates

- **routeguard-core** — Config, IPC (JSON-RPC over named pipe), tunnel traits, orchestrator
- **routeguard-routing** — App / IP / domain routing engine (pure logic)
- **routeguard-wfp** — WFP network lock and app filters (Windows)
- **routeguard-platform** — WireGuardNT, route table, DNS proxy
- **routeguard-awg** / **routeguard-phantun** — Extension traits only
- **routeguard-service** — Elevated Windows service
- **routeguard-cli** — Unprivileged CLI client
- **routeguard-gui** — Tauri stub (Phase 4)

## Data flow

1. CLI sends JSON-RPC to `\\.\pipe\RouteGuard`
2. Service orchestrator connects WireGuardNT adapter
3. Routing engine compiles rules → `PolicySnapshot`
4. WFP applies split-tunnel app filters + network lock
5. Route table adds dual-default routes (physical + tunnel) and bypass CIDRs

See [docs/SPLIT_TUNNEL.md](docs/SPLIT_TUNNEL.md) for per-app routing.

## Default routing

Full tunnel (`0.0.0.0/0`) with exclude rules for bypass.

## Network lock

WFP block-all with exceptions: loopback, LAN, DNS, WG endpoint, tunnel interface.
Persistent state in `%ProgramData%\RouteGuard\network_lock.json`.

## Future

- WFP callout driver (`drivers/routeguard-callout/`) for true app redirect
- AWG backend behind `feature = "awg"` — see [docs/AWG_BACKEND.md](docs/AWG_BACKEND.md)
- Phantun transport supervisor behind `feature = "phantun"`
- Tauri GUI in `routeguard-gui`
