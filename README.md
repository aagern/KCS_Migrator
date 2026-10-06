# kcs-migrator

A Rust CLI that exports the configuration of a running Kaspersky Container Security (KCS)
instance and replays it onto another one in dependency order.

Supports **KCS 2.4 and 2.5+**, detecting which REST API generation an instance speaks and
translating bundle contents between them where the schemas differ.

---

## KCS versions and API generations

KCS serves several API generations side by side under `/api/v1/`, `/api/v2/` and `/api/v3/`:

| KCS release | Generations served | What this tool uses |
|---|---|---|
| 2.4 and earlier | `v1` | `v1` |
| 2.5 | `v1` (compatibility shim), `v2`, `v3` | **`v3`** |
| 2.6 (expected) | `v3`; `v1` deprecated | `v3` |

`GET /api/{v}/healthz` answers `{"version":"2.5.0"}` on every generation, so the tool
probes it and picks `v1` below KCS 2.5.0 and `v3` from 2.5.0 on. Pass
`--api-version v1|v3` to skip detection entirely — useful when `/healthz` is blocked by a
proxy. An explicit `--api-version` sends **no** probe request at all.

`v2` is not used. It exists on the server, but no product documentation references it, so
there is no basis for choosing it over `v1` or `v3`.

### What changes between v1 and v3

These are the differences that matter to a migration. Each was established by diffing live
per-item `GET` responses for the same object through both generations on a KCS 2.5.0
instance — the published v3 OpenAPI document is stale in places and was not used as the
source of truth.

| Resource | APIv1 | APIv3 |
|---|---|---|
| agent group | `fileThreatProtectionProxyUrl` | `networkSettingsProxyUrl` |
| agent group | `networkReputationSource` | `networkSettingsSource` |
| agent group | `fileThreatProtectionMalwareDbUrl` | *removed* |
| assurance policy | `failCICDStep` | `failExternalScansStep` |
| assurance policy | inline `customControls` | own resource, `/policies/assurance-control` |
| runtime profile | `auditWritEvents` | `auditWriteEvents` |
| runtime profile | `auditRenameOrEvents` | `auditRenameOrMoveEvents` |
| runtime policy | admission controls inline | own resource, `/policies/admission-controller` |
| image registry | — | *no change* |

The last row matters: the v3 OpenAPI document omits `pullMode` and `repositoryPathMode`
from the registry schema, but the server returns both and the v1/v3 payloads are
byte-identical. Trusting the document would have corrupted every registry.

Translation is **forward-only**. Importing a v3 bundle into a v1 target is refused before
any request is sent, because KCS 2.5 resources such as admission-controller policies and
custom benchmark frameworks have no equivalent in 2.4. Export from the older instance
instead.

---

## Quick start

```bash
# Put the token in a file rather than on the command line: an argument is
# visible to every process on the host and lands in shell history.
printf '%s' 'kcs_YOURTOKENHERE' > ~/.kcs-token && chmod 600 ~/.kcs-token

# Export. The API generation is detected from the instance.
kcs-migrator export \
  --url https://kcs.source.example/api \
  --token-file ~/.kcs-token \
  --no-verify-tls \
  --output /tmp/kcs-bundles

# See exactly what an import would do, without writing anything.
kcs-migrator import-bundle /tmp/kcs-bundles/kcs-export-2026-10-06_12-00-00 \
  --url https://kcs.target.example/api \
  --token-file ~/.kcs-target-token \
  --no-verify-tls \
  --dry-run

# Then do it for real.
kcs-migrator import-bundle /tmp/kcs-bundles/kcs-export-2026-10-06_12-00-00 \
  --url https://kcs.target.example/api \
  --token-file ~/.kcs-target-token \
  --no-verify-tls
```

The token is on the **My profile** page of the KCS web console.

### Before you import

**An interrupted import cannot be re-run.** The POSTs are not idempotent and the
source-to-target ID mapping lives only in memory, so a second run creates duplicates of
everything the first run succeeded at, and the foreign keys in the later steps point at the
first run's resources. If an import fails partway, inspect the target and finish by hand —
do not re-run it. Use `--dry-run` first; that is what it is for.

---

## URL convention

Pass the base URL **with the `/api` suffix and without a version segment** — the tool adds
`/v1` or `/v3` itself.

| Connection method | `--url` |
|---|---|
| By DNS name | `https://kcs.demo.lab/api` |
| By ingress IP with a Host override | `https://10.160.200.5/api` plus `--host-header kcs.demo.lab` |
| Through an SSH tunnel | `https://localhost:8443/api` |

---

## CLI reference

```
kcs-migrator <SUBCOMMAND>

  export          Export KCS configuration to a timestamped bundle directory
  import-bundle   Restore a bundle to a target KCS instance
```

### Connection options (both subcommands)

| Option | Default | Notes |
|---|---|---|
| `--url <URL>` | — | Base URL including `/api`. Env: `KCS_URL` |
| `--token <TOKEN>` | — | Env: `KCS_TOKEN`. Prefer `--token-file` |
| `--token-file <PATH>` | — | First line of the file, trimmed. Takes precedence over `--token` |
| `--no-verify-tls` | off | Accept self-signed certificates |
| `--host-header <HOST>` | — | Override the HTTP `Host` header |
| `--api-version <auto\|v1\|v3>` | `auto` | `auto` probes `GET /healthz`; `v1`/`v3` send no probe |
| `--timeout-secs <N>` | `120` | Whole-request deadline, including body download |
| `--connect-timeout-secs <N>` | `10` | TCP connect plus TLS handshake |

The request timeout is generous because the network-reputation export returns a blob of
unbounded size. Lower it if your instance is close by.

### `export`

| Option | Default | Notes |
|---|---|---|
| `--output <DIR>` | `.` | Bundle is written to `<DIR>/kcs-export-<UTC timestamp>/` |
| `--namespace <NS>` | `kcs` | Namespace for the `kubectl exec` user export |
| `--users-pod-selector <NAME>` | `kcs-postgresql` | StatefulSet name of the KCS Postgres pod |
| `--skip-users` | off | Skip the user export; no `kubectl` access needed |

### `import-bundle`

| Argument / option | Default | Notes |
|---|---|---|
| `<BUNDLE>` | — | Path to the bundle directory |
| `--dry-run` | off | Resolve and describe every call; send no writes |
| `--strict-notifications` | off | Abort instead of continuing when a response policy references an unmappable notification channel |

---

## Bundle format

A bundle is one timestamped directory. `manifest.json` is written **last**, so its absence
marks an interrupted export — and an import refuses such a directory before contacting the
target.

```
kcs-export-2026-10-06_12-00-00/
├── manifest.json                              format version, source release, API generation
├── integrations/
│   ├── image-registries.json
│   ├── ldap.json
│   ├── sso.json
│   ├── llm.json
│   ├── siem.json
│   ├── external-groups.json
│   ├── agent-groups.json
│   ├── notifications-REFERENCE.json            reference only — no create endpoint
│   └── sign-validators-REFERENCE.json          reference only — no create endpoint
├── policies/
│   ├── scanner.json
│   ├── assurance.json
│   ├── assurance-controls.json                 KCS 2.5+
│   ├── admission-controller.json               KCS 2.5+
│   ├── admission-controls.json                 KCS 2.5+
│   ├── runtime-profiles.json
│   ├── runtime.json
│   ├── response.json
│   ├── custom-reputation.json                  which reputation list is active
│   └── network-reputation.bin                  opaque blob, replayed verbatim
├── benchmark/
│   ├── frameworks.json                         KCS 2.5+, custom only
│   └── controls.json                           KCS 2.5+, custom only
├── CEL/
│   ├── benchmark/control/<slug>.cel
│   ├── policies/assurance-control/<slug>.cel
│   └── policies/admission-controller/control/<slug>.cel
├── components/scanner-priority.json
├── config/reports-storage.json
├── security/scopes-REFERENCE.json              GET-only; used to remap scopes by name
└── users-REFERENCE.json                        reference only — exported via kubectl exec
```

### `manifest.json`

```json
{
  "tool_version": "0.2.0",
  "bundle_format": 2,
  "timestamp": "2026-10-06_12-00-00",
  "source_url": "https://kcs.source.example/api",
  "kcs_version": "2.4.1",
  "api_version": "v1"
}
```

`api_version` is the field the importer cannot work without: it decides whether the bodies
need translating. A manifest with no `bundle_format` was written by 0.1.0, which only
spoke APIv1; such bundles still import.

### CEL rules

KCS 2.5 lets you write benchmark, assurance and admission controls in CEL. The API carries
each rule as a JSON string, so a multi-line expression arrives as one line of escapes —
unreadable and impossible to review in a diff. Export writes the rule to a `.cel` file
verbatim and leaves a pointer:

```json
{ "name": "no-root-containers", "rule": { "$celFile": "CEL/benchmark/control/CTRL-0001.cel" } }
```

Import reads the file back before POSTing, so **the rules are editable by hand between
export and import** — which is the point of keeping them outside the JSON. Pointers must
stay inside the bundle; an absolute path or one containing `..` is refused.

`CEL/benchmark/framework/` does not exist: a framework is a named set of references to
controls and has no `rule` field of its own. The CEL lives in the controls.

### `-REFERENCE` files

Exported for visibility, never replayed, because the API has no create endpoint
(notification channels, image signature validators, security scopes) or because the bundle
holds no credentials for them (user accounts).

---

## Import dependency order

Whatever owns an ID is created before whatever references it.

| # | Step | Notes |
|---|---|---|
| 1 | Reports storage config | |
| 2 | Scanner priority | |
| 3 | Security scopes | read-only; matches bundle scopes to the target **by name** |
| 4 | LDAP | `POST`, then `/{id}/enable` |
| 5 | SSO | `POST`, then `/enable` |
| 6 | LLM | |
| 7 | SIEM integrations | |
| 8 | Image registries | registers IDs; HTTP 400 skips with a warning |
| 9 | External scan groups | |
| 10 | Agent groups | translated; HTTP 400 skips with a warning |
| 11 | Benchmark controls | KCS 2.5+; CEL inlined |
| 12 | Benchmark frameworks | KCS 2.5+; then `/{id}/enable` |
| 13 | Assurance controls | KCS 2.5+; CEL inlined |
| 14 | Scanner policies | then `/{id}/enable` |
| 15 | Assurance policies | translated; then `/{id}/enable` |
| 16 | Admission controls | KCS 2.5+; CEL inlined |
| 17 | Admission-controller policies | KCS 2.5+ |
| 18 | Runtime profiles | translated; registers IDs |
| 19 | Runtime policies | rewrites `runtimeProfileId`; splits off an admission policy from an APIv1 bundle |
| 20 | Notification channels | warning only — no create endpoint exists |
| 21 | Response policies | unmappable channels dropped with a warning |
| 22 | Custom-reputation list selection | |
| 23 | Network-reputation blob | raw `PUT` |

Steps 11–13 and 16–17 are the resource classes KCS 2.5 introduced. Against an APIv1 target
they are skipped without a request, because 2.4 has no route for them and a 404 would abort
the import.

### Graceful skips

Some resources cannot be replayed even with a complete body. Image registries using
credential-based auth and previously-deployed agent groups return HTTP 400, because the
bundle holds no credentials and the target mints its own deployment token. Those emit an
`OPERATOR ACTION REQUIRED` warning naming the resource and the import continues. Scanner
and assurance policies do **not** skip on 400 — there a 400 means the body is wrong, and
hiding it would hide a translation bug.

---

## Secrets and manual steps

Sensitive fields (`bindPassword`, `clientSecret`, registry passwords, LLM API keys) are
returned as `***` by the KCS API and stored as placeholders. Re-enter them in the target
console after import.

`deploymentToken` is **not** masked by the API — it comes back in full, and it is a live
credential that enrols a node-agent into the instance that issued it. It is therefore
stripped at export rather than written to the bundle. Nothing is lost: the target mints its
own when an agent group is created.

| Resource | Why manual |
|---|---|
| Notification channels (email / Telegram / webhook) | No create endpoint in any generation |
| Image signature validators | No create endpoint |
| Security scopes | `/security/scopes` is GET-only. Create them on the target **with the same names** before importing, and references are remapped automatically |
| User accounts | Credentials not in the bundle; exported as reference via `kubectl exec` |
| License key | Activate in the target console |
| Syslog, Vault, proxy, Cilium | Helm values, not in the API |

SIEM integrations **are** migrated — they have a full CRUD API in both generations and
their create body carries no credentials. Earlier versions of this document said SIEM was
configurable only through Helm values; that was wrong.

---

## Building

### Prerequisites

- Rust 1.98.1 or newer (`rust-version` in `Cargo.toml`), via [rustup](https://rustup.rs)
- No system OpenSSL: TLS is rustls, statically linked

```bash
cargo build --release      # ./target/release/kcs-migrator
```

### On a remote Linux host

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
sudo apt-get install -y gcc          # C linker, once
scp -r kcs_migrator/ user@host:/tmp/kcs_migrator
ssh user@host "cd /tmp/kcs_migrator && ~/.cargo/bin/cargo build --release"
```

`Cargo.lock` is committed, so a build from a clean checkout is reproducible.

---

## Tests

```bash
cargo +nightly fmt -- --check
cargo build                                            # see note
cargo build --release
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --doc
cargo doc --no-deps                                    # must emit zero warnings
```

145 unit tests, 8 doctests and 2 compile-fail cases. HTTP is mocked at the transport layer
with `wiremock` and bundles are built in temp directories, so no live KCS instance is
needed.

`cargo build` is listed separately on purpose: dev-dependencies are visible to the test
build and absent from the real one, so a `use wiremock::…` that drifts into `src/` passes a
green test run and fails the first time someone builds the crate.

The crate sets `#![forbid(unsafe_code)]` and enables `clippy::pedantic` and
`clippy::nursery`. The compile-fail cases under `tests/ui/` pin two borrow guarantees on
`IdMapper`; if they fail after a toolchain upgrade, read `tests/ui.rs` before regenerating
the snapshots.

---

## Architecture

A reusable library (`kcs_migrator`) plus a thin binary (`kcs-migrator`) that owns only
argument parsing and `main`.

| Module | Responsibility |
|---|---|
| `version` | Parses the KCS release and picks an API generation |
| `cli` | Connection options shared by both subcommands, and how they become a client |
| `client` | Async `reqwest` wrapper; injects `Tron-Token`, applies the version prefix and the timeouts |
| `bundle` | `manifest.json`: format version, source release, API generation |
| `cel` | CEL rules as `.cel` text files instead of escaped JSON strings |
| `export` | Walks a source instance into a bundle directory |
| `translate` | Rewrites bundle bodies between API generations, forward-only |
| `importer` | Replays a bundle in dependency order, rewriting foreign keys |
| `id_mapper` | Source-to-target ID registry used for those rewrites |
| `users` | Reference-only user export via `kubectl exec` |

The API generation lives in exactly one place: `KcsClient` applies the `/v1` or `/v3`
prefix, and call sites pass version-relative paths like `/policies/scanner`. A test fails
if a versioned literal reappears in `export.rs` or `importer.rs`.

See the module-level docs (`cargo doc --open`) for the full reference. Each module that
does I/O carries a cancel-safety verdict, and the two public entry points — `export_all`
and `import_bundle` — carry their own: export is cancel-safe and leaves a detectably
incomplete bundle; **import is not cancel-safe**, which is why an interrupted import must
not be re-run.
