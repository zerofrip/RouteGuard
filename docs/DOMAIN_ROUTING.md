# Domain Routing (Phase 6 + 6.5)

Production domain-based split tunneling: DNS interception, TTL-aware IP cache, dynamic host routes, and MasselGUARD bridge visibility.

## Overview

```
Client DNS → WFP callout (UDP/TCP :53) → 127.0.0.1:5353 (DnsProxy v2)
           → upstream resolver (Network Lock permits)
           → DomainRoutingManager (rule-gated cache)
           → SessionRoutes /32,/128 host routes
           → RoutingEngine.decide() O(1) IP lookup
```

Domain rules are **static patterns** (`*.netflix.com`, `example.com`, `*.local`). Resolved IPs are cached with per-record TTL, persisted to `%ProgramData%\RouteGuard\domain_cache.json`, and installed as OS host routes when a tunnel context is active.

## Configuration

Add to `config.toml` under `[routing.domain_dns]`:

```toml
[routing.domain_dns]
enabled = true
listen = "127.0.0.1:5353"
listen_v6 = "[::1]:5353"
upstream = ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]
redirect_port_53 = true    # enable WFP redirect + callout when driver present
kernel_redirect = false    # fail if routeguard-callout.sys absent
explicit_proxy = false     # set true when resolver manually points at proxy
min_ttl_secs = 30
max_ttl_secs = 3600
max_resolved_ips = 50000
max_domains = 10000
```

| Flag | Behavior |
|------|----------|
| `redirect_port_53` | Install WFP filters; use kernel callout when driver loaded, else user-mode filters only |
| `kernel_redirect` | Require `routeguard-callout.sys`; service fails apply if driver missing |
| `explicit_proxy` | Treat domain routing as effective without port-53 redirect (manual DNS config) |

## Phase 6.5 — Kernel callout driver

`drivers/routeguard-callout/` provides `routeguard-callout.sys`:

| Layer | Path |
|-------|------|
| `FWPM_LAYER_DATAGRAM_DATA_V4/V6` | UDP/53 packet rewrite to loopback proxy |
| `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6` | TCP/53 connect redirect |

User-mode (`DnsCalloutManager` in `routeguard-wfp`):

1. Probes `\\.\RouteGuardCallout`
2. IOCTL `SET_CONFIG` with proxy port + excluded service PID
3. Installs weighted WFP permit filters (weight 2, above NL block-all)
4. Persists filter IDs to `%ProgramData%\RouteGuard\dns_redirect.json`

Loop prevention: skip loopback destinations, skip proxy port, exclude RouteGuard service PID (upstream forwarding).

## Security

- **Rule-gated caching**: only QNAMEs matching a static domain rule are cached.
- **Loopback-only proxy**: IOCTL rejects non-loopback proxy targets.
- **Caps + LRU**: `max_resolved_ips` / `max_domains` prevent route-table exhaustion.
- **Import reconcile**: stale cache entries whose pattern no longer matches are pruned.
- **Fail-open**: callout classify errors permit original flow.

## IPC

| Method | Description |
|--------|-------------|
| `domain.status` | Cache stats, `kernelRedirect`, `driverPresent`, `redirectStats` |
| `service.capabilities` | `calloutDriver`, `domainRoutingEffective` |

## Events

| Type | When |
|------|------|
| `routing.dns.resolved` | After cache upsert |
| `routing.domain_route_added` | Host route installed |
| `routing.domain_route_expired` | TTL purge |
| `routing.domain_recovered` | Startup reload from disk |
| `routing.reloaded` | Extended with `domainRules`, `domainRoutes` |

MasselGUARD maps these to `routeguard.domain_*` aliases on the agent event bus.

## Effective flag

`domainRoutingEffective = true` when:

1. Domain rules exist and DNS proxy is enabled, **and**
2. Kernel redirect active **or** WFP redirect filters active **or** `explicit_proxy` is set, **and**
3. Tunnel is connected **or** all domain rules target bypass-only

## Components

| Crate | Module | Role |
|-------|--------|------|
| `routeguard-routing` | `domain_store.rs` | TTL cache, persistence, O(1) `by_ip` |
| `routeguard-routing` | `domain_policy.rs` | Compile dynamic host CIDR lists |
| `routeguard-service` | `domain_routing.rs` | Orchestrator, purge timer, events |
| `routeguard-platform` | `dns.rs` | DnsProxy v2 (dual-stack, per-record TTL) |
| `routeguard-platform` | `routes.rs` | `install_domain_route` / purge |
| `routeguard-wfp` | `dns_callout.rs` | IOCTL client + `DnsCalloutManager` |
| `routeguard-wfp` | `dns_callout_wfp.rs` | User-mode WFP filter install |
| `drivers/routeguard-callout` | kernel | UDP/TCP :53 rewrite callouts |

## MasselGUARD

- `routeguard.status` includes `domain: { rules, resolvedIps, effective, kernelRedirect, driverPresent }`
- Split-tunnel UI shows kernel redirect / callout-ready badges
- Bridge polls `domain.status` after sync and on availability changes

## Network Lock ordering

DNS redirect filters use weight **2** (UserPermit tier), above NL block-all. Upstream resolvers from `[routing.domain_dns] upstream` are merged into `policy.dns_servers` in `build_policy()` so NL permit rules allow service upstream forwarding.

## Testing

- Linux CI: `cargo test -p routeguard-wfp` (IOCTL struct + manager unit tests)
- Windows VM: `tests/scripts/dns_redirect_matrix.ps1` (driver + device path)
- See `drivers/routeguard-callout/SIGNING.md` for test/production signing

## Limitations

- TCP/53 connect redirect relies on ALE layer + user-mode companion; UDP datagram rewrite is primary path.
- CNAME chasing is bounded; complex chains may need upstream re-query (Phase 6.2+).
- Per-IP WFP permits remain optional when host routes suffice.
