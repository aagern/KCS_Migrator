# kcs-migrator

A Rust CLI tool that exports the full configuration of a running Kaspersky Container Security (KCS) 2.4 instance via its REST API and replays it on a fresh instance in the correct dependency order.

---

## Quick Start

DATA for tool:

**KCS URL**: `https://kcs.demo.lab/api`
**Token**: `kcs_TEST1234567890`
**Namespace**: `kcs`

### Export command

```bash
# Export all KCS configuration to /tmp/kcs-bundles/
./target/release/kcs-migrator export \
  --url https://kcs.demo.lab/api \
  --token kcs_TEST1234567890 \
  --no-verify-tls \
  --output /tmp/kcs-bundles \
  --namespace kcs
```

### Import command

```bash
./target/release/kcs-migrator import-bundle \
  /tmp/kcs-bundles/kcs-export-2026-05-21_16-58-53 \
  --url https://kcs-target.demo.lab/api \
  --token <TARGET_TOKEN> \
  --no-verify-tls
```

---

## Architecture

The crate is split into a reusable library (`kcs_migrator`) and a thin CLI binary (`kcs-migrator`). The binary owns only the clap argument parsing and the `main` entry point; everything else lives in the library so it can be consumed from integration tests, doctests, or downstream tooling.

```
src/
├── main.rs        CLI entry point (clap subcommands: export, import-bundle)
├── lib.rs         Library crate root — re-exports the modules below
├── client.rs      KcsClient — async reqwest wrapper, injects Tron-Token header
├── export.rs      export_all() — orchestrates per-section helpers, writes versioned bundle
├── importer.rs    import_bundle() — 14-step pipeline of single-responsibility helpers
├── id_mapper.rs   IdMapper — source-id → target-id registry for FK rewriting
└── users.rs       export_users_reference() — kubectl exec into postgres pod
```

`export_all` and `import_bundle` are short orchestrators that call per-section / per-step helpers in a fixed order. Each helper carries its own `///` docblock describing its inputs, outputs, and failure modes. See the module-level `//!` docs (`cargo doc --open`) for the full reference.

**Graceful-skip behavior**: image registries with credential-based auth (`user_password`, `service_account`, …) and previously-deployed agent groups return HTTP 400 on re-POST because credentials and `deploymentToken`s cannot be replayed. The importer catches the 400, emits an `OPERATOR ACTION REQUIRED` warning, and continues with the next resource. All other failures abort the import.

---

## Building

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs))
- No system OpenSSL needed — TLS is handled by rustls (statically linked)

### Local build (macOS / Linux)

```bash
# Debug build (fast compile, slower binary)
cargo build

# Release build (optimised, ~5 MB binary)
cargo build --release

# Binary location
./target/release/kcs-migrator
```

### Building on the target Linux host (no cross-compile needed)

```bash
# 1. Install Rust on the remote machine
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal

# 2. Install the C linker (required once)
sudo apt-get install -y gcc

# 3. Copy source and build
scp -r kcs_migrator/ user@host:/tmp/kcs_migrator
ssh user@host "cd /tmp/kcs_migrator && ~/.cargo/bin/cargo build --release"
```

### Running the test suite

```bash
cargo test           # all unit + doctests
cargo test --doc     # doctests only (requires the library crate)
cargo +nightly fmt -- --check
cargo clippy --all-targets -- -D warnings
```

26 unit tests + 3 doctests run in ~0.15 s. They mock HTTP at the transport level (wiremock) and use tmpdir bundles — no live KCS instance required.

---

## URL convention

KCS exposes its frontend on `/` and its REST API under `/api/v1/`. Always pass the base URL **with the `/api` suffix**:

| Connection method | `--url` value |
|---|---|
| Via DNS name | `https://kcs.demo.lab/api` |
| Via ingress IP + `--host-header` | `https://10.160.200.5/api` |
| Via SSH tunnel (`localhost:8443`) | `https://localhost:8443/api` |

---

## CLI reference

```
kcs-migrator <SUBCOMMAND>

SUBCOMMANDS:
    export          Export KCS configuration to a timestamped bundle directory
    import-bundle   Restore a bundle to a target KCS instance
```

### `export`

Fetches all exportable resources from the source KCS instance and writes them to a bundle directory named `kcs-export-YYYY-MM-DD_HH-MM-SS/` inside `--output`.

```
kcs-migrator export [OPTIONS]

OPTIONS:
    --url <URL>                       KCS base URL including /api  [env: KCS_URL]
    --token <TOKEN>                   API token (Tron-Token header value)  [env: KCS_TOKEN]
    --output <DIR>                    Directory to write the bundle into  [default: .]
    --no-verify-tls                   Skip TLS certificate verification
    --host-header <HOST>              Override the HTTP Host header (useful when connecting via IP)
    --namespace <NS>                  Kubernetes namespace for the kubectl user export  [default: kcs]
    --users-pod-selector <NAME>       StatefulSet name of the KCS Postgres pod  [default: kcs-postgresql]
    --skip-users                      Skip the kubectl exec user export step
```

### `import-bundle`

Reads a bundle directory and recreates all resources on the target KCS instance in dependency order.

```
kcs-migrator import-bundle <BUNDLE> [OPTIONS]

ARGS:
    <BUNDLE>    Path to the bundle directory (e.g. ./kcs-export-2026-05-21_16-58-53)

OPTIONS:
    --url <URL>      Target KCS base URL including /api  [env: KCS_URL]
    --token <TOKEN>  API token  [env: KCS_TOKEN]
    --no-verify-tls  Skip TLS certificate verification
```

---

## Bundle format

A bundle is a single timestamped directory:

```
kcs-export-2026-05-21_16-58-53/
├── manifest.json                              tool version + timestamp + source URL
├── integrations/
│   ├── image-registries.json
│   ├── ldap.json
│   ├── sso.json
│   ├── llm.json
│   ├── agent-groups.json
│   ├── notifications-REFERENCE.json           reference only — cannot be auto-imported
│   └── sign-validators-REFERENCE.json         reference only — cannot be auto-imported
├── policies/
│   ├── scanner.json
│   ├── assurance.json
│   ├── runtime-profiles.json
│   ├── runtime.json
│   ├── response.json
│   └── network-reputation.bin                 raw binary
├── components/
│   └── scanner-priority.json
├── config/
│   └── reports-storage.json
└── users-REFERENCE.json                       reference only — exported via kubectl exec
```

**`-REFERENCE` files** are exported for visibility but cannot be replayed automatically because the API has no create/update endpoint for them (notification channels, sign validators) or because credentials are not stored in the bundle (users). Operator recreates these manually.

---

## Import dependency order

Resources are created in this fixed sequence so that foreign-key references resolve correctly:

1. Reports storage config
2. Scanner priority
3. LDAP (full replace via PUT)
4. SSO
5. LLM
6. Image registries → registers `image-registry` IDs in IdMapper; credential-based registries gracefully skip on HTTP 400 (no credentials in bundle)
7. Agent groups → registers `agent-group` IDs; gracefully skips on HTTP 400 (server-issued `deploymentToken` cannot be replayed)
8. Scanner policies → enables each if `enabled: true`
9. Assurance policies → enables each if `enabled: true`
10. Runtime profiles → registers `runtime-profile` IDs
11. Runtime policies — rewrites `runtimeProfileId` in each match block via IdMapper
12. Notification channels — prints operator warning, no API import
13. Response policies — rewrites `notificationSettingsIds` via IdMapper; aborts if any ID is unmapped
14. Network reputation binary (raw PUT)

---

## Demo environment — example commands

**KCS URL**: `https://kcs.demo.lab/api`
**Token**: `kcs_TEST1234567890`
**Namespace**: `kcs`

### Do export

```bash
# Export all KCS configuration to /tmp/kcs-bundles/
./target/release/kcs-migrator export \
  --url https://kcs.demo.lab/api \
  --token kcs_TEST1234567890 \
  --no-verify-tls \
  --output /tmp/kcs-bundles \
  --namespace kcs
```

Expected output:
```
Bundle exported to: /tmp/kcs-bundles/kcs-export-2026-05-21_16-58-53
User reference exported successfully.
```

### Export without user export (no kubectl access needed)

```bash
./target/release/kcs-migrator export \
  --url https://kcs.demo.lab/api \
  --token kcs_TEST1234567890 \
  --no-verify-tls \
  --output /tmp/kcs-bundles \
  --skip-users
```

### Export via ingress IP with Host header override

Useful when DNS resolution for `kcs.demo.lab` is not available:

```bash
./target/release/kcs-migrator export \
  --url https://10.160.200.5/api \
  --token kcs_TEST1234567890 \
  --no-verify-tls \
  --host-header kcs.demo.lab \
  --output /tmp/kcs-bundles \
  --skip-users
```

### Import a bundle to a target instance

```bash
./target/release/kcs-migrator import-bundle \
  /tmp/kcs-bundles/kcs-export-2026-05-21_16-58-53 \
  --url https://kcs-target.demo.lab/api \
  --token <TARGET_TOKEN> \
  --no-verify-tls
```

### Using environment variables instead of flags

```bash
export KCS_URL=https://kcs.demo.lab/api
export KCS_TOKEN=kcs_TEST1234567890

kcs-migrator export --no-verify-tls --output /tmp/kcs-bundles
kcs-migrator import-bundle /tmp/kcs-bundles/kcs-export-2026-05-21_16-58-53 --no-verify-tls
```

---

## Secrets and manual steps

Sensitive fields (`bindPassword`, `clientSecret`, registry passwords, LLM API keys) are returned as `***` by the KCS API and stored as placeholders in the bundle. After import, re-enter them in the target web UI.

| Resource | Why manual |
|---|---|
| Notification channels (email / Telegram / webhook) | No POST/PUT API endpoint |
| Image signature validators | No POST/PUT API endpoint |
| User accounts | Credentials not stored in bundle; exported as reference via `kubectl exec` |
| License key | Manual activation in target UI |
| SIEM / syslog / Vault / proxy / Cilium | Helm values only, not in the API |
