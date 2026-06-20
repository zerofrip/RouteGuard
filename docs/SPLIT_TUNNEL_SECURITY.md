# Split Tunnel Security Review

## Threat Model

| Actor | Capability | Goal |
|-------|------------|------|
| Local unprivileged user | IPC via named pipe | Add bypass rules, exfiltrate without VPN |
| Malicious config | Crafted paths | Match unintended binaries |
| Crash / kill | Service termination | Leave WFP filters or routes orphaned |

## Mitigations

### Path validation (`rules_ops.rs`)

- Reject non-absolute paths
- Require `.exe` suffix
- Require file to exist at add time
- Store normalized lowercase path
- Cap at 256 app rules (`MAX_APP_RULES`)

### IPC

- Named pipe `\\.\pipe\RouteGuard` — document ACL hardening for production (currently open to authenticated users on same machine)
- Typed JSON-RPC params; invalid mode rejected
- Failed apply rolls back config and WFP filter IDs

### WFP filter lifecycle

- Filter IDs tracked in `SessionRoutes` and `app_rules_state.json`
- Disconnect clears split filters before adapter teardown
- `recovery::cleanup_stale()` removes tracked filters on service recovery
- All filters use `RouteGuard_SPLIT_` name prefix

### Network lock interaction

- Excluded-app permits merge with kill-switch exceptions when lock is enabled
- Excluded apps must be explicitly configured; no wildcard bypass by default
- Audit: `tracing::info!` on rule add/remove (service layer)

### Supply chain

- Prefer full paths over glob patterns
- CLI warns when glob patterns used (future enhancement)

## Residual risks

- Glob rules may match unintended binaries in the same directory tree
- SplitInclude without callout driver: included apps may not fully use VPN for all destinations
- Plaintext `config.toml` stores rule paths (no DPAPI yet)
- No integrity check on target executable before permitting bypass

## Rollback

On `apply_split_policy()` failure:

1. Restore previous WFP filter set from snapshot IDs
2. Revert `config.toml` on add/remove IPC failure
3. Clear partial split routes via `SessionRoutes::clear_split`

Disconnect always attempts filter + route cleanup even if individual steps fail (logged, non-fatal).
