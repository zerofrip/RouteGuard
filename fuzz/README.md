# RouteGuard fuzz targets (Phase 13)

Requires [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and nightly Rust.

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run fuzz_wg_conf -- -max_total_time=60
cargo +nightly fuzz run fuzz_lwo_wire -- -max_total_time=60
```

## Targets

| Target | Entry |
|--------|-------|
| `fuzz_wg_conf` | `routeguard_platform::wgnt::config::parse_conf_text` |
| `fuzz_awg_conf` | `parse_awg_from_conf` + `validate_awg_params` |
| `fuzz_lwo_conf` | `parse_routeguard_section`, `parse_lwo_keys` |
| `fuzz_lwo_wire` | `routeguard_lwo::wire::deobfuscate` |
| `fuzz_ipc_request` | `serde_json::from_slice::<IpcRequest>` |
| `fuzz_diagnostics_params` | `DiagnosticsExportParams` deserialize |

Seed corpus: `corpus/wg/minimal.conf`

Crash reproducers: `artifacts/` (gitignored).
