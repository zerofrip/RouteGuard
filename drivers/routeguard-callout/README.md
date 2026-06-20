# RouteGuard WFP Callout Driver (Phase 6.5)

Kernel-mode WFP callout driver for transparent DNS redirect to RouteGuard DnsProxy (`127.0.0.1:5353`).

## Status

Phase 6.5 implementation — builds with Windows Driver Kit (WDK) on Windows.

## Components

| File | Purpose |
|------|---------|
| `include/rg_callout_ioctl.h` | Shared IOCTL + config structs |
| `include/rg_callout_guids.h` | WFP callout GUIDs |
| `src/driver.c` | DriverEntry / unload |
| `src/device.c` | `\Device\RouteGuardCallout` + IOCTL handlers |
| `src/config.c` | Config validation, loop prevention helpers |
| `src/callout_register.c` | FwpsCalloutRegister |
| `src/callout_datagram_v4.c` | UDP/53 IPv4 packet rewrite |
| `src/callout_datagram_v6.c` | UDP/53 IPv6 packet rewrite |
| `src/callout_connect_redirect_v4.c` | TCP/53 IPv4 connect redirect |
| `src/callout_connect_redirect_v6.c` | TCP/53 IPv6 connect redirect |
| `routeguard-callout.inf` | Driver installation INF |

## Layers

- `FWPM_LAYER_DATAGRAM_DATA_V4/V6` — UDP DNS (`sendto` path)
- `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6` — TCP/53 and connected UDP

Future Phase 4 app split tunnel will add bind/connect redirect callouts to the same driver.

## Build (Windows + WDK)

```bat
cd drivers\routeguard-callout
build -cZ
```

Or integrate into Visual Studio WDK driver project referencing all `src/*.c` files.

## Install

```bat
pnputil /add-driver routeguard-callout.inf /install
sc start RouteGuardCallout
```

Requires EV code signing for production Windows 10/11.

## User-mode integration

- `routeguard-wfp/src/dns_callout.rs` — IOCTL client + `DnsCalloutManager`
- `routeguard-service` — `apply_domain_dns_wfp()` enables redirect when `[routing.domain_dns] redirect_port_53` or `kernel_redirect = true`

## IOCTL

| IOCTL | Purpose |
|-------|---------|
| `IOCTL_RG_DNS_SET_CONFIG` | Enable/disable, proxy port, excluded PIDs |
| `IOCTL_RG_DNS_GET_STATUS` | Driver version, enabled state |
| `IOCTL_RG_DNS_GET_STATS` | Redirect/skip counters |

Device path: `\\.\RouteGuardCallout`

## Configuration (config.toml)

```toml
[routing.domain_dns]
redirect_port_53 = true
kernel_redirect = true   # fail if driver absent
```

## Security

- Proxy target must be loopback (validated in IOCTL)
- Service PID excluded from redirect (upstream DNS forwarding)
- Fail-open on classify internal errors (permit original flow)

## Reference

- [Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
- [RouteGuard DOMAIN_ROUTING.md](../../docs/DOMAIN_ROUTING.md)
