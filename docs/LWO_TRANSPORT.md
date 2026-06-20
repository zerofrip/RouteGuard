# LWO Transport (Phase 9)

Lightweight WireGuard Obfuscation — in-process UDP relay with Mullvad-compatible wire format.

## Overview

```
Profile (.conf + [RouteGuard]) → TransportSelector
  → lwo: in-process relay obfuscates WG packets (header XOR + OBFUSCATION_BIT)
  → WireGuard binds 127.0.0.1:N (local UDP)
  → relay forwards obfuscated UDP to RemoteUDP (peer or explicit)
  → zero packet overhead on the wire
```

Unlike Phantun, LWO does **not** spawn an external binary or wrap traffic in TCP.

## Configuration

### `[RouteGuard]` in `.conf`

```ini
[RouteGuard]
Transport = lwo
Lwo = true
RemoteUDP = 203.0.113.1:51820   # optional; defaults to peer Endpoint
LocalListen = 127.0.0.1:0
ProtocolVersion = 0               # optional; default 0
```

Requires valid `Interface` PrivateKey and `Peer` PublicKey (same as WireGuard).

### `config.toml` / profile transport

```toml
[tunnel.transport]
preference = "auto"       # auto | direct_udp | phantun | lwo
require_lwo = false

[tunnel.transport.lwo]
remote_udp = "203.0.113.1:51820"
local_listen = "127.0.0.1:0"
protocol_version = 0
```

## Transport selection (auto mode)

| Hints present | Result |
|---------------|--------|
| LWO only | lwo |
| Phantun only | phantun (if binary present) |
| LWO + Phantun | **lwo wins** (LWO hints beat Phantun) |
| none | direct_udp |

`require_lwo = true` hard-fails connect if LWO validation fails (missing keys, remote, etc.).

## Wire format

Mullvad-compatible (`mullvad` wire format):

- Header XOR with 32-byte key derived from WG PrivateKey / PublicKey
- `OBFUSCATION_BIT` (`0x80`) set in second header byte
- Payload bytes unchanged — **zero overhead**

## Runtime conf

On connect, RouteGuard writes `%ProgramData%\RouteGuard\runtime\<name>.conf`:

- `[RouteGuard]` section stripped
- `Endpoint` rewritten to local LWO listen address (`127.0.0.1:N`)
- `MTU` adjusted (default −80 bytes)

## IPC (schema v3)

| Method | LWO fields |
|--------|------------|
| `tunnel.connect` response | `lwoActive`, `protocolVersion`, `wireFormat` |
| `tunnel.status` | `lwoActive`, `protocolVersion`, `wireFormat` |
| `service.capabilities` | `features.lwo`, `transportCapabilities[]` with `protocolVersion` / `wireFormat` |

## Events

| type | Payload |
|------|---------|
| `transport.starting` | `{ kind: "lwo" }` |
| `transport.connected` | `{ kind: "lwo", localEndpoint, remoteTransport, protocolVersion: 0, wireFormat: "mullvad" }` |
| `transport.fallback` | `{ requested, actual, reason }` |
| `transport.failed` | `{ kind: "lwo", reason, recoverable }` |
| `transport.recovering` | `{ kind: "lwo", attempt, maxAttempts }` |
| `transport.disconnected` | `{ kind: "lwo" }` |

## Health & recovery

Every 5 s the service polls LWO (and Phantun) relay health. On failure:

1. `transport.recovering` (attempt 1–3, backoff 5 / 10 / 15 s)
2. Transport down + relay restart
3. Policy refresh
4. After 3 failures → `transport.failed` (non-recoverable)

User-initiated disconnect does not trigger auto-retry.

## Network lock

WFP permits UDP to:

- Local WireGuard endpoint (`127.0.0.1:N`)
- Remote UDP server (`RemoteUDP`)

## MasselGUARD bridge

RouteGuard transport events with `kind=lwo` map to `routeguard.lwo_*` agent events. `negotiated.lwo` reflects `service.capabilities.features.lwo`.
