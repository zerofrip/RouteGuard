# RouteGuard

Modern WireGuard-based VPN platform for Windows — high-performance routing, application split tunneling, IP/domain rules, and WFP network lock.

## Crates

| Crate | Description |
|-------|-------------|
| `routeguard-core` | Config, IPC protocol, tunnel traits, orchestrator |
| `routeguard-routing` | App / IP / domain routing engine |
| `routeguard-wfp` | Windows Filtering Platform network lock |
| `routeguard-platform` | WireGuardNT, route table, DNS (Windows) |
| `routeguard-awg` | AmneziaWG params, validation, conf parse/build |
| `routeguard-phantun` | Phantun transport traits (no impl yet) |
| `routeguard-service` | Windows Service (elevated) |
| `routeguard-cli` | Command-line client |
| `routeguard-gui` | Tauri GUI stub (future) |

## Build

Requires Rust 1.75+ and (on Windows) Administrator privileges for WFP operations.

```bash
cargo build --release
```

Place `wireguard.dll` in `wireguard-deps/` or next to the service binary.

## Usage

```bash
# Start the Windows service (elevated)
routeguard-service.exe

# CLI talks to service via named pipe
routeguard-cli connect my-tunnel
routeguard-cli status
routeguard-cli network-lock enable

# Application split tunneling (FullTunnel + exclude)
routeguard-cli rules add-app "C:\Program Files (x86)\Steam\steam.exe" --mode exclude
routeguard-cli rules list
routeguard-cli rules remove-app "C:\Program Files (x86)\Steam\steam.exe"
```

See [docs/SPLIT_TUNNEL.md](docs/SPLIT_TUNNEL.md) for split tunnel details.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design details.

## License

Apache-2.0
