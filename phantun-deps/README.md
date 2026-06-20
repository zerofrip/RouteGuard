# Phantun Dependencies

Place **phantun_client.exe** here for UDP-over-TCP transport (Phase 8).

## Build

Build from [Phantun](https://github.com/dndx/phantun) (client binary):

```bash
cargo build --release -p phantun_client
cp target/release/phantun_client RouteGuard/phantun-deps/phantun_client.exe
```

On Linux cross-builds, rename to `phantun_client.exe` for the Windows installer layout.

## Install layout

The RouteGuard installer copies:

- `phantun-deps/phantun_client.exe` → `{InstallDir}\phantun_client.exe`

RouteGuard resolves the binary beside `routeguard-service.exe`.

## Probe

`service.capabilities.features.phantun` is `true` when `phantun_client.exe` exists next to the service.

## Security

- Load only from executable directory (no `PATH` search)
- Sign `phantun_client.exe` with the same EV certificate as RouteGuard when shipping production builds
