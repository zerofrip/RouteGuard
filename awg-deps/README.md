# AmneziaWG Dependencies

Place the **amneziawg-windows** embeddable `tunnel.dll` here for AWG profile support.

## Build

Build from [amneziawg-windows](https://github.com/amnezia-vpn/amneziawg-windows):

```bat
cd amneziawg-windows
.\build.cmd
copy x64\tunnel.dll RouteGuard\awg-deps\tunnel.dll
```

## Install layout

The RouteGuard installer copies:

- `awg-deps/tunnel.dll` → `{InstallDir}\tunnel.dll`
- `wireguard-deps/wireguard.dll` → `{InstallDir}\wireguard.dll`

## Security

- Load only from executable directory (no `PATH` search)
- Sign `tunnel.dll` with same EV certificate as RouteGuard
- Verify catalog/hash at install time (optional)

## Probe

`service.capabilities.features.awg` is `true` when `tunnel.dll` loads successfully.
