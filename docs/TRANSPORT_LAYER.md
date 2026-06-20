# Transport Layer (Phase 8 + 9)

UDP path to the WireGuard peer — orthogonal to tunnel backend (WireGuardNT / AWG).

## Overview

```
Profile (.conf + optional [RouteGuard]) → TransportSelector
  → direct_udp: WireGuard speaks UDP to peer Endpoint unchanged
  → phantun: phantun_client.exe wraps UDP in TCP → local UDP for WireGuard
  → lwo: in-process Mullvad-compatible UDP obfuscation → local UDP for WireGuard
  → runtime .conf rewrite (Endpoint + MTU) → TunnelBackendSelector → tunnel up
  → NL permits: UDP to local/wg endpoint + TCP (Phantun) or UDP remote (LWO)
```

See [LWO_TRANSPORT.md](LWO_TRANSPORT.md) for LWO details.

## Configuration

### `[RouteGuard]` section in `.conf`

**Phantun:**

```ini
[RouteGuard]
Transport = phantun
RemoteTCP = 203.0.113.1:443
LocalListen = 127.0.0.1:0
```

**LWO:**

```ini
[RouteGuard]
Transport = lwo
RemoteUDP = 203.0.113.1:51820
LocalListen = 127.0.0.1:0
ProtocolVersion = 0
```

### `config.toml` / profile transport

```toml
[tunnel.transport]
preference = "auto"       # auto | direct_udp | phantun | lwo
require_phantun = false
require_lwo = false

[tunnel.transport.phantun]
remote_tcp = "203.0.113.1:443"
local_listen = "127.0.0.1:0"

[tunnel.transport.lwo]
remote_udp = "203.0.113.1:51820"
local_listen = "127.0.0.1:0"
protocol_version = 0
```

## Transport selection

| preference | Hints | Binary / runtime | Result |
|------------|-------|------------------|--------|
| direct_udp | any | any | direct_udp |
| lwo | valid keys | always | lwo |
| lwo | invalid keys | — | Error if `require_lwo`, else direct_udp + fallback |
| phantun | any | phantun_client.exe | phantun |
| phantun | any | no binary | Error if `require_phantun`, else direct_udp + fallback |
| auto | none | any | direct_udp |
| auto | LWO (+/- Phantun) | — | **lwo** (LWO beats Phantun) |
| auto | Phantun only | yes | phantun |
| auto | Phantun only | no | direct_udp + fallback |

## Runtime conf

On connect, RouteGuard writes `%ProgramData%\RouteGuard\runtime\<name>.conf`:

- `[RouteGuard]` section stripped
- `Endpoint` rewritten to effective WireGuard endpoint (peer, local Phantun UDP, or local LWO UDP)
- `MTU` adjusted for transport overhead

## IPC (schema v3)

| Method | Transport fields |
|--------|------------------|
| `tunnel.connect` | optional `transport` override; response includes `phantunActive`, `lwoActive`, `protocolVersion`, `wireFormat` |
| `tunnel.status` | `transport`, `phantunActive`, `lwoActive`, `localEndpoint`, `remoteTransport`, `protocolVersion`, `wireFormat` |
| `service.capabilities` | `features.phantun`, `features.lwo`, `features.transports`, `transportCapabilities[]` |

## Events

| type | When |
|------|------|
| `transport.starting` | Transport layer bring-up begins |
| `transport.connected` | Local endpoint ready |
| `transport.failed` | Transport up failed |
| `transport.fallback` | Requested transport unavailable |
| `transport.recovering` | Health loop restarting relay (LWO / Phantun) |
| `transport.disconnected` | Transport torn down |

## Network lock

When network lock is active, WFP permits:

- UDP to WireGuard endpoint (direct peer, local Phantun UDP, or local LWO UDP)
- TCP to Phantun `RemoteTCP` server (`transport_permits`)
- UDP to LWO `RemoteUDP` server

See [phantun-deps/README.md](../phantun-deps/README.md) for Phantun binary layout.

## Health monitoring

Every 5 s, LWO and Phantun relays are health-checked. Failed relays trigger up to 3 recovery attempts (5 / 10 / 15 s backoff) before a non-recoverable `transport.failed` event.
