//! # Overview
//!
//! Read-only side of the migrator: walks a source KCS instance and
//! writes every replayable resource into a self-contained bundle
//! directory. The bundle layout matches what [`crate::importer`]
//! expects to replay; see `README.md` for the directory tree.
//!
//! # Why the per-item GETs
//!
//! KCS `GET /<resource>` (list) returns a truncated projection of
//! each item — often missing fields the `POST` endpoint requires
//! (e.g. `scanTimeout` on image registries, `agentType` on agent
//! groups). For resource classes that get re-`POST`ed during import,
//! `get_list_detailed` composes the list response with per-item
//! `GET /<resource>/<id>` calls so the bundle records the full
//! POST-ready schema. List-only resources (reference dumps) can use
//! `get_list` directly.

use crate::client::{is_client_error, KcsClient};
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// `CARGO_PKG_VERSION` of the migrator that produced the bundle —
/// written into `manifest.json` so an importer can warn if it sees a
/// bundle from an incompatible version.
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// # Overview
///
/// Serializes `data` as pretty-printed JSON and writes it to `path`,
/// creating any missing parent directories. Used as the bundle
/// "primitive write".
///
/// # Errors
///
/// Returns an error if directory creation fails, if serialization
/// fails (unlikely for [`serde_json::Value`]), or if the write fails.
fn write_json(path: &Path, data: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(data)?)?;
    Ok(())
}

/// # Overview
///
/// Fetches a KCS list endpoint and normalizes the response to a JSON
/// array. KCS list endpoints return either `[item, ...]` directly or
/// `{"items": [item, ...]}`; both shapes (and missing `items`) are
/// flattened to a single array shape.
///
/// On HTTP 400 or 404 the function returns an empty array so callers
/// can write an empty bundle file rather than aborting the export.
/// (Some resource endpoints 404 when the feature has never been
/// configured on the source instance.)
///
/// # Errors
///
/// Returns the underlying transport error for non-4xx failures
/// (timeouts, TLS errors, 5xx).
async fn get_list(client: &KcsClient, api_path: &str) -> Result<Value> {
    match client.get(api_path).await {
        Ok(data) => {
            if data.is_array() {
                Ok(data)
            } else if let Some(items) = data.get("items") {
                Ok(items.to_owned())
            } else {
                Ok(json!([]))
            }
        }
        Err(e) => {
            if is_client_error(&e) {
                return Ok(json!([]));
            }
            Err(e)
        }
    }
}

/// # Overview
///
/// Same shape as [`get_list`] but for endpoints that return a single
/// object (e.g. SSO config, LLM integration, reports-storage config).
/// Returns `{}` on HTTP 400/404 so callers can record "feature not
/// configured" in the bundle without aborting.
///
/// # Errors
///
/// Returns the underlying transport error for non-4xx failures.
async fn get_single(client: &KcsClient, api_path: &str) -> Result<Value> {
    match client.get(api_path).await {
        Ok(data) if data.is_object() => Ok(data),
        Ok(_) => Ok(json!({})),
        Err(e) => {
            if is_client_error(&e) {
                return Ok(json!({}));
            }
            Err(e)
        }
    }
}

/// # Overview
///
/// Fetches a KCS list endpoint and enriches each entry with a per-item
/// `GET item_path_prefix/<id>`. KCS list endpoints return a truncated
/// projection of each resource; the per-item endpoint returns the
/// full schema required by `POST`. This helper composes both so
/// callers receive POST-ready records ready to be replayed.
///
/// On a per-item 4xx the function falls back to the truncated list
/// entry rather than aborting — best-effort export. Importers may
/// subsequently fail to replay those entries (the truncated body is
/// missing required fields), but at least the rest of the bundle gets
/// written.
///
/// # Errors
///
/// Returns the transport error from the list request, or any non-4xx
/// error from the per-item GETs.
///
/// # Examples
///
/// ```ignore
/// let registries = get_list_detailed(
///     &client,
///     "/integrations/image-registries",
///     "/integrations/image-registries",
/// ).await?;
/// ```
async fn get_list_detailed(
    client: &KcsClient,
    list_path: &str,
    item_path_prefix: &str,
) -> Result<Value> {
    let list = get_list(client, list_path).await?;
    let items = match list.as_array() {
        Some(a) => a.to_owned(),
        None => return Ok(json!([])),
    };

    let mut detailed = Vec::with_capacity(items.len());
    for item in items {
        let id = match item.get("id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => {
                detailed.push(item);
                continue;
            }
        };
        match client.get(&format!("{item_path_prefix}/{id}")).await {
            Ok(full) if full.is_object() => detailed.push(full),
            Ok(_) => detailed.push(item),
            Err(e) if is_client_error(&e) => detailed.push(item),
            Err(e) => return Err(e),
        }
    }
    Ok(Value::Array(detailed))
}

/// # Overview
///
/// Exports the full KCS configuration surface from `client` into a
/// newly-created `kcs-export-<UTC-timestamp>/` directory under
/// `output_dir`. Returns the bundle path.
///
/// The bundle is self-contained: every replayable resource is written
/// as JSON, the network-reputation blob is written as raw bytes, and
/// a `manifest.json` records the tool version, timestamp, and source
/// URL. Files named `*-REFERENCE.json` are informational only — the
/// importer will not attempt to replay them.
///
/// # Errors
///
/// Returns the first error encountered while talking to the source
/// API (other than 4xx on list/single endpoints, which are treated as
/// "feature not configured") or while writing bundle files.
///
/// # Examples
///
/// ```no_run
/// use kcs_migrator::client::{KcsClient, Timeouts};
/// use kcs_migrator::export;
/// use std::path::Path;
///
/// # async fn run() -> anyhow::Result<()> {
/// let (client, kcs) = KcsClient::detect(
///     "https://kcs.src.corp", "tok", true, None, Timeouts::default(),
/// ).await?;
/// println!("source is KCS {kcs}, speaking {:?}", client.api_version());
/// let bundle = export::export_all(&client, Path::new(".")).await?;
/// println!("bundle: {}", bundle.display());
/// # Ok(()) }
/// ```
pub async fn export_all(client: &KcsClient, output_dir: &Path) -> Result<PathBuf> {
    let ts = Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let bundle = output_dir.join(format!("kcs-export-{ts}"));

    export_integrations(client, &bundle).await?;
    export_notifications_reference(client, &bundle).await?;
    export_policies(client, &bundle).await?;
    export_network_reputation(client, &bundle).await?;
    export_components(client, &bundle).await?;
    export_config(client, &bundle).await?;
    export_security_scopes(client, &bundle).await?;
    // Written last, deliberately: the absence of `manifest.json` is what marks a
    // bundle directory as incomplete, and the importer refuses such a directory
    // before writing anything to the target.
    write_manifest(&bundle, &ts, client.base_url())?;

    Ok(bundle)
}

/// Fields a bundle must never carry, keyed by the resource they appear on.
///
/// `deploymentToken` is a live credential: it enrols a node-agent into the
/// instance that issued it. The KCS API returns it in full from
/// `GET /integrations/agent-group/<id>` — unlike `bindPassword` or
/// `clientSecret`, which come back masked as `***` — so without this step
/// every bundle on disk is a credential-bearing artifact.
///
/// Removing it costs nothing: [`crate::importer`] already discards the
/// field before `POSTing`, because the target mints its own token. What is
/// kept is the agent manifest data an import actually needs.
const REDACT_FROM_AGENT_GROUP: &[&str] = &["deploymentToken"];

/// Strips [`REDACT_FROM_AGENT_GROUP`] from every entry of an agent-group
/// list, returning how many values were removed.
fn redact_agent_groups(groups: &mut Value) -> usize {
    let Some(items) = groups.as_array_mut() else {
        return 0;
    };
    let mut removed = 0;
    for group in items.iter_mut() {
        let Some(obj) = group.as_object_mut() else {
            continue;
        };
        for field in REDACT_FROM_AGENT_GROUP {
            if obj.remove(*field).is_some() {
                removed += 1;
            }
        }
    }
    removed
}

/// # Overview
///
/// Dumps the `integrations/` section of the bundle: image registries,
/// LDAP, SSO, LLM, agent groups, and sign validators (reference only).
///
/// Image registries and agent groups are fetched via
/// [`get_list_detailed`] because their list-endpoint projection drops
/// fields the import POST requires (`scanTimeout`, `agentType`, …).
/// Sign validators are stored as `*-REFERENCE.json` — they cannot be
/// replayed automatically and the importer skips them.
///
/// # Errors
///
/// Returns the first transport, parse, or filesystem error.
async fn export_integrations(client: &KcsClient, bundle: &Path) -> Result<()> {
    let registries = get_list_detailed(
        client,
        "/integrations/image-registries",
        "/integrations/image-registries",
    )
    .await?;
    write_json(
        &bundle.join("integrations/image-registries.json"),
        &registries,
    )?;

    let ldap = get_list(client, "/integrations/ldap").await?;
    write_json(&bundle.join("integrations/ldap.json"), &ldap)?;

    let sso = get_single(client, "/integrations/sso").await?;
    write_json(&bundle.join("integrations/sso.json"), &sso)?;

    let llm = get_single(client, "/integrations/llm").await?;
    write_json(&bundle.join("integrations/llm.json"), &llm)?;

    let mut agent_groups = get_list_detailed(
        client,
        "/integrations/agent-group",
        "/integrations/agent-group",
    )
    .await?;
    let redacted = redact_agent_groups(&mut agent_groups);
    if redacted > 0 {
        eprintln!(
            "Note: removed {redacted} deployment token(s) from the agent-group export. \
             They are server-issued credentials and cannot be replayed; the target mints \
             its own when each agent group is created."
        );
    }
    write_json(
        &bundle.join("integrations/agent-groups.json"),
        &agent_groups,
    )?;

    let sign_validators = get_list(client, "/integrations/sign-validators").await?;
    write_json(
        &bundle.join("integrations/sign-validators-REFERENCE.json"),
        &sign_validators,
    )?;

    Ok(())
}

/// # Overview
///
/// Dumps the three notification-channel lists (email, telegram,
/// webhook) into a single `integrations/notifications-REFERENCE.json`.
///
/// Notification channels have no create endpoint in the KCS API, so
/// the file is informational only — the importer emits an
/// `OPERATOR ACTION REQUIRED` warning summarizing what needs manual
/// recreation on the target.
///
/// # Errors
///
/// Returns the first transport, parse, or filesystem error.
async fn export_notifications_reference(client: &KcsClient, bundle: &Path) -> Result<()> {
    let email = get_list(client, "/integrations/notification-settings/email").await?;
    let telegram = get_list(client, "/integrations/notification-settings/telegram").await?;
    let webhook = get_list(client, "/integrations/notification-settings/webhook").await?;
    write_json(
        &bundle.join("integrations/notifications-REFERENCE.json"),
        &json!({"email": email, "telegram": telegram, "webhook": webhook}),
    )?;
    Ok(())
}

/// # Overview
///
/// Dumps the JSON-typed policy collections: scanner, assurance,
/// runtime-profile, runtime, and response. The
/// network-reputation binary blob is handled separately in
/// [`export_network_reputation`] because it is opaque bytes rather
/// than JSON.
///
/// All five use `get_list_detailed`. They used to use the truncated list
/// view, which drops fields the import POST requires — a runtime
/// profile's `fileOperationsRules`, for instance, is absent from the list
/// projection, so the profile both failed to import and skipped the
/// audit-event rename the `APIv1` bundle needs. Composing the list with
/// per-item GETs is the fix.
///
/// # Errors
///
/// Returns the first transport, parse, or filesystem error.
async fn export_policies(client: &KcsClient, bundle: &Path) -> Result<()> {
    // (list endpoint, per-item endpoint, bundle file)
    for (path, file) in [
        ("/policies/scanner", "policies/scanner.json"),
        ("/policies/assurance", "policies/assurance.json"),
        (
            "/policies/runtime-profile",
            "policies/runtime-profiles.json",
        ),
        ("/policies/runtime", "policies/runtime.json"),
        ("/policies/response", "policies/response.json"),
    ] {
        let detailed = get_list_detailed(client, path, path).await?;
        write_json(&bundle.join(file), &detailed)?;
    }

    Ok(())
}

/// # Overview
///
/// Downloads the network-reputation blob via
/// `GET /policies/custom-reputation/export` and writes it to
/// `policies/network-reputation.bin` inside the bundle.
///
/// The blob is opaque to the migrator — it's replayed verbatim during
/// import via [`crate::client::KcsClient::put_bytes`].
///
/// A 4xx is treated as "the feature was never configured" and no file is
/// written, which is how every other section already behaves. Before this,
/// a source instance with no custom reputation list aborted the whole
/// export at the last step — after every other file had been written but
/// before `manifest.json`, leaving a bundle that looked merely incomplete.
///
/// # Errors
///
/// Returns a non-4xx transport error from the GET, or a filesystem error
/// if the parent directory cannot be created or the file cannot be
/// written.
async fn export_network_reputation(client: &KcsClient, bundle: &Path) -> Result<()> {
    let bytes = match client.get_bytes("/policies/custom-reputation/export").await {
        Ok(bytes) => bytes,
        Err(e) => {
            if is_client_error(&e) {
                return Ok(());
            }
            return Err(e);
        }
    };
    let path = bundle.join("policies/network-reputation.bin");
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("network reputation path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)?;
    std::fs::write(&path, bytes)?;
    Ok(())
}

/// # Overview
///
/// Dumps the `components/` section — currently just the scanner
/// priority configuration. Carved out as its own section so future
/// non-policy component dumps (e.g. license servers) can be added
/// here without bloating [`export_integrations`] or
/// [`export_policies`].
///
/// # Errors
///
/// Returns the first transport, parse, or filesystem error.
async fn export_components(client: &KcsClient, bundle: &Path) -> Result<()> {
    let scanner_priority = get_single(client, "/scanners/priority").await?;
    write_json(
        &bundle.join("components/scanner-priority.json"),
        &scanner_priority,
    )?;
    Ok(())
}

/// # Overview
///
/// Dumps the `config/` section — currently just the reports-storage
/// destination (S3 / SMB / etc).
///
/// # Errors
///
/// Returns the first transport, parse, or filesystem error.
async fn export_config(client: &KcsClient, bundle: &Path) -> Result<()> {
    let reports_storage = get_single(client, "/reports/storage/config").await?;
    write_json(
        &bundle.join("config/reports-storage.json"),
        &reports_storage,
    )?;
    Ok(())
}

/// # Overview
///
/// Dumps the `security/` section — the instance's security scopes, as
/// `scopes-REFERENCE.json`.
///
/// Reference-only: `/security/scopes` is **GET-only**, so scopes cannot be
/// created through the API and the operator has to recreate them by hand
/// on the target. The file is still essential rather than informational,
/// because four resource classes reference scopes by ID
/// (`systemScopes`): assurance policies, runtime policies and profiles,
/// and — from 2.5 — admission-controller policies, benchmark frameworks
/// and external groups. The importer reads this file to learn each source
/// scope's *name*, looks that name up on the target, and rewrites the IDs.
/// Without it those references would point at the source instance's ID
/// space and silently scope every policy to nothing.
///
/// # Errors
///
/// Returns the first transport, parse, or filesystem error.
async fn export_security_scopes(client: &KcsClient, bundle: &Path) -> Result<()> {
    let scopes = get_list(client, "/security/scopes").await?;
    write_json(&bundle.join("security/scopes-REFERENCE.json"), &scopes)?;
    Ok(())
}

/// # Overview
///
/// Writes the bundle's `manifest.json`, recording the migrator
/// version that produced the bundle, the export timestamp, and the
/// source KCS URL. Operators (and future importer versions) use the
/// manifest to detect bundle-tool version drift.
///
/// # Errors
///
/// Returns a filesystem error if the file cannot be written.
fn write_manifest(bundle: &Path, ts: &str, source_url: &str) -> Result<()> {
    write_json(
        &bundle.join("manifest.json"),
        &json!({
            "tool_version": TOOL_VERSION,
            "timestamp": ts,
            "source_url": source_url,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Timeouts;
    use crate::version::ApiVersion;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn stub_empty(server: &MockServer) {
        let empty_list = ResponseTemplate::new(200).set_body_json(json!({"items": []}));
        let empty_obj = ResponseTemplate::new(200).set_body_json(json!({}));
        let empty_bin = ResponseTemplate::new(200).set_body_bytes(vec![]);

        for p in [
            "/v1/integrations/ldap",
            "/v1/integrations/sso",
            "/v1/integrations/llm",
            "/v1/integrations/agent-group",
            "/v1/integrations/sign-validators",
            "/v1/integrations/notification-settings/email",
            "/v1/integrations/notification-settings/telegram",
            "/v1/integrations/notification-settings/webhook",
            "/v1/policies/scanner",
            "/v1/policies/assurance",
            "/v1/policies/runtime-profile",
            "/v1/policies/runtime",
            "/v1/policies/response",
        ] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(empty_list.clone())
                .mount(server)
                .await;
        }
        // Detail endpoints for the per-item sweep, and the scopes list.
        Mock::given(method("GET"))
            .and(path("/v1/security/scopes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(server)
            .await;
        for p in ["/v1/scanners/priority", "/v1/reports/storage/config"] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(empty_obj.clone())
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/v1/policies/custom-reputation/export"))
            .respond_with(empty_bin)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn export_writes_image_registries() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"id": "r1", "description": "hub", "apiUrl": "https://hub.docker.com"}]
            })))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir()?;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let bundle = export_all(&client, tmp.path()).await?;

        let data: Value = serde_json::from_str(&std::fs::read_to_string(
            bundle.join("integrations/image-registries.json"),
        )?)?;
        assert_eq!(data[0]["id"], "r1");
        Ok(())
    }

    #[tokio::test]
    async fn export_creates_manifest_with_timestamp_and_version() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir()?;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let bundle = export_all(&client, tmp.path()).await?;

        let manifest: Value =
            serde_json::from_str(&std::fs::read_to_string(bundle.join("manifest.json"))?)?;
        assert!(manifest.get("timestamp").is_some());
        assert_eq!(manifest["tool_version"], TOOL_VERSION);
        Ok(())
    }

    #[tokio::test]
    async fn export_bundle_name_starts_with_kcs_export() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir()?;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let bundle = export_all(&client, tmp.path()).await?;

        let file_name = bundle
            .file_name()
            .ok_or_else(|| anyhow!("bundle path has no file name"))?;
        assert!(file_name.to_string_lossy().starts_with("kcs-export-"));
        Ok(())
    }

    #[tokio::test]
    async fn export_writes_notifications_reference_with_all_keys() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/notification-settings/email"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"id": "em-1", "email": "ops@corp.com"}]
            })))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir()?;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let bundle = export_all(&client, tmp.path()).await?;

        let notif: Value = serde_json::from_str(&std::fs::read_to_string(
            bundle.join("integrations/notifications-REFERENCE.json"),
        )?)?;
        assert!(notif.get("email").is_some());
        assert!(notif.get("telegram").is_some());
        assert!(notif.get("webhook").is_some());
        Ok(())
    }

    #[tokio::test]
    async fn export_writes_network_reputation_binary() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/policies/custom-reputation/export"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"binary-data".to_vec()))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir()?;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let bundle = export_all(&client, tmp.path()).await?;

        let bin = std::fs::read(bundle.join("policies/network-reputation.bin"))?;
        assert_eq!(bin, b"binary-data");
        Ok(())
    }

    // ---- group 6: deployment tokens must not reach the bundle ----

    #[tokio::test]
    async fn agent_group_export_strips_the_deployment_token() -> Result<()> {
        // GET /integrations/agent-group/<id> returns deploymentToken in full --
        // unlike bindPassword or clientSecret, which come back masked as ***. It is
        // a live credential that enrols a node-agent into the issuing instance, so
        // without this step every bundle on disk is credential-bearing.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/agent-group"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"id": "g1", "groupName": "k8s"}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/agent-group/g1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "g1",
                "groupName": "k8s",
                "deploymentToken": "SECRET-DEPLOY-TOKEN",
                "kcsNamespace": "kcs",
                "networkEnabled": true,
            })))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir()?;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let bundle = export_all(&client, tmp.path()).await?;

        let raw = std::fs::read_to_string(bundle.join("integrations/agent-groups.json"))?;
        assert!(
            !raw.contains("SECRET-DEPLOY-TOKEN"),
            "the deployment token must not be written to disk"
        );
        let data: Value = serde_json::from_str(&raw)?;
        assert!(data[0].get("deploymentToken").is_none());
        // The manifest data an import actually needs is kept.
        assert_eq!(data[0]["groupName"], "k8s");
        assert_eq!(data[0]["kcsNamespace"], "kcs");
        assert_eq!(data[0]["networkEnabled"], json!(true));
        Ok(())
    }

    // ---- group 6: policies are exported POST-ready ----

    #[tokio::test]
    async fn policy_export_composes_per_item_detail_not_the_list_projection() -> Result<()> {
        // The list projection drops fields POST requires. A runtime profile's
        // fileOperationsRules is the clearest case: absent from the list, so the
        // profile both failed to import and skipped the APIv3 audit-event rename
        // that depends on walking those rules.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/policies/runtime-profile"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"id": "p1", "name": "busybox"}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/policies/runtime-profile/p1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "p1",
                "name": "busybox",
                "fileOperationsRules": {"items": [{"paths": ["/etc"]}]},
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir()?;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let bundle = export_all(&client, tmp.path()).await?;

        let data: Value = serde_json::from_str(&std::fs::read_to_string(
            bundle.join("policies/runtime-profiles.json"),
        )?)?;
        assert_eq!(
            data[0]["fileOperationsRules"]["items"][0]["paths"][0],
            json!("/etc"),
            "the detail-only field must be in the bundle"
        );
        Ok(())
    }

    // ---- group 6: an unconfigured feature must not abort the export ----

    #[tokio::test]
    async fn a_404_on_the_reputation_export_leaves_the_rest_of_the_bundle_intact() -> Result<()> {
        // This was the one section that aborted on 4xx. It runs near the end, so a
        // source with no custom reputation list produced a bundle with every other
        // file written but no manifest.json -- indistinguishable from an export
        // that was interrupted.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/policies/custom-reputation/export"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir()?;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let bundle = export_all(&client, tmp.path()).await?;

        assert!(
            !bundle.join("policies/network-reputation.bin").exists(),
            "an unconfigured feature writes no file"
        );
        assert!(
            bundle.join("manifest.json").exists(),
            "the export must still complete -- the manifest is what marks it complete"
        );
        Ok(())
    }

    #[tokio::test]
    async fn security_scopes_are_exported_for_reference() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/security/scopes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": "s1", "name": "Default scope"}
            ])))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir()?;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let bundle = export_all(&client, tmp.path()).await?;

        let data: Value = serde_json::from_str(&std::fs::read_to_string(
            bundle.join("security/scopes-REFERENCE.json"),
        )?)?;
        // Reference-only -- /security/scopes is GET-only -- but the importer needs
        // the id-to-name pairing to remap systemScopes onto the target.
        assert_eq!(data[0]["name"], "Default scope");
        assert_eq!(data[0]["id"], "s1");
        Ok(())
    }
}
