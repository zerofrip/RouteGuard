# RouteGuard Roadmap

## Phase 0 — Scaffold (complete)
- Cargo workspace, CI, trait crates, docs

## Phase 1 — MVP Tunnel + Network Lock
- WireGuardNT connect/disconnect
- WFP network lock with LAN/DNS/endpoint exceptions
- Persistent lock recovery
- CLI: connect, disconnect, status, network-lock

## Phase 1b — IP + App Routing
- Routing engine + WFP app permit/block
- Route table bypass routes
- CLI: rules reload/list/test

## Phase 2 — Domain Routing + DNS Proxy
- Local DNS proxy on `127.0.0.1:5353`
- Dynamic domain → IP rule updates
- TTL-aware cache

## Phase 3 — Hardening
- Filter diffing, benchmarks, fuzz tests, security review

## Phase 7 — AWG Backend (complete)

- AmneziaWG `tunnel.dll` backend alongside WireGuardNT
- Profile vault with AWG validation
- Auto backend selection + fallback events
- MasselGUARD AWG editor + badges

## Phase 4 — GUI + Callout Driver
- Tauri 2 GUI
- WFP callout `.sys` for DNS redirect (Phase 6.5)
- Phantun transport supervisor (planned)
