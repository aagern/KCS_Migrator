//! # Overview
//!
//! Read-only side of the migrator: walks a source KCS instance and
//! writes every replayable resource into a self-contained bundle
//! directory. The bundle layout matches what [`crate::importer`]
//! expects to replay; see `README.md` for the directory tree.
//!
//! # Why the per-item GETs
//!
//! KCS `GET /v1/<resource>` (list) returns a truncated projection of
//! each item — often missing fields the `POST` endpoint requires
//! (e.g. `scanTimeout` on image registries, `agentType` on agent
//! groups). For resource classes that get re-`POST`ed during import,
//! [`get_list_detailed`] composes the list response with per-item
//! `GET /v1/<resource>/<id>` calls so the bundle records the full
//! POST-ready schema. List-only resources (reference dumps) can use
//! [`get_list`] directly.

use crate::client::KcsClient;
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
            if let Some(status) = e
                .downcast_ref::<reqwest::Error>()
                .and_then(|re| re.status())
            {
                if status.as_u16() == 400 || status.as_u16() == 404 {
                    return Ok(json!([]));
                }
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
            if let Some(status) = e
                .downcast_ref::<reqwest::Error>()
                .and_then(|re| re.status())
            {
                if status.as_u16() == 400 || status.as_u16() == 404 {
                    return Ok(json!({}));
                }
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
///     "/v1/integrations/image-registries",
///     "/v1/integrations/image-registries",
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
            Err(e) => {
                let is_4xx = e
                    .downcast_ref::<reqwest::Error>()
                    .and_then(|re| re.status())
                    .map(|s| s.is_client_error())
                    .unwrap_or(false);
                if is_4xx {
                    detailed.push(item);
                } else {
                    return Err(e);
                }
            }
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
/// use kcs_migrator::client::KcsClient;
/// use kcs_migrator::export;
/// use std::path::Path;
///
/// # async fn run() -> anyhow::Result<()> {
/// let client = KcsClient::new("https://kcs.src.corp", "tok", true, None)?;
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
    write_manifest(&bundle, &ts, client.base_url())?;

    Ok(bundle)
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
        "/v1/integrations/image-registries",
        "/v1/integrations/image-registries",
    )
    .await?;
    write_json(
        &bundle.join("integrations/image-registries.json"),
        &registries,
    )?;

    let ldap = get_list(client, "/v1/integrations/ldap").await?;
    write_json(&bundle.join("integrations/ldap.json"), &ldap)?;

    let sso = get_single(client, "/v1/integrations/sso").await?;
    write_json(&bundle.join("integrations/sso.json"), &sso)?;

    let llm = get_single(client, "/v1/integrations/llm").await?;
    write_json(&bundle.join("integrations/llm.json"), &llm)?;

    let agent_groups = get_list_detailed(
        client,
        "/v1/integrations/agent-group",
        "/v1/integrations/agent-group",
    )
    .await?;
    write_json(
        &bundle.join("integrations/agent-groups.json"),
        &agent_groups,
    )?;

    let sign_validators = get_list(client, "/v1/integrations/sign-validators").await?;
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
    let email = get_list(client, "/v1/integrations/notification-settings/email").await?;
    let telegram = get_list(client, "/v1/integrations/notification-settings/telegram").await?;
    let webhook = get_list(client, "/v1/integrations/notification-settings/webhook").await?;
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
/// All five collections use [`get_list`] (truncated list view). The
/// known schema-drift caveat in the module-level docs applies: some
/// fields required by POST are missing from the list projection and
/// these will fail on import. Migrating these to [`get_list_detailed`]
/// is the next mechanical fix (tracked in `CLAUDE.md`).
///
/// # Errors
///
/// Returns the first transport, parse, or filesystem error.
async fn export_policies(client: &KcsClient, bundle: &Path) -> Result<()> {
    let scanner = get_list(client, "/v1/policies/scanner").await?;
    write_json(&bundle.join("policies/scanner.json"), &scanner)?;

    let assurance = get_list(client, "/v1/policies/assurance").await?;
    write_json(&bundle.join("policies/assurance.json"), &assurance)?;

    let runtime_profiles = get_list(client, "/v1/policies/runtime-profile").await?;
    write_json(
        &bundle.join("policies/runtime-profiles.json"),
        &runtime_profiles,
    )?;

    let runtime = get_list(client, "/v1/policies/runtime").await?;
    write_json(&bundle.join("policies/runtime.json"), &runtime)?;

    let response = get_list(client, "/v1/policies/response").await?;
    write_json(&bundle.join("policies/response.json"), &response)?;

    Ok(())
}

/// # Overview
///
/// Downloads the network-reputation blob via
/// `GET /v1/policies/custom-reputation/export` and writes it to
/// `policies/network-reputation.bin` inside the bundle.
///
/// The blob is opaque to the migrator — it's replayed verbatim during
/// import via [`crate::client::KcsClient::put_bytes`].
///
/// # Errors
///
/// Returns a transport error from the GET, or a filesystem error if
/// the parent directory cannot be created or the file cannot be
/// written.
async fn export_network_reputation(client: &KcsClient, bundle: &Path) -> Result<()> {
    let bytes = client
        .get_bytes("/v1/policies/custom-reputation/export")
        .await?;
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
    let scanner_priority = get_single(client, "/v1/scanners/priority").await?;
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
    let reports_storage = get_single(client, "/v1/reports/storage/config").await?;
    write_json(
        &bundle.join("config/reports-storage.json"),
        &reports_storage,
    )?;
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
        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
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
        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
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
        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
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
        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
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
        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let bundle = export_all(&client, tmp.path()).await?;

        let bin = std::fs::read(bundle.join("policies/network-reputation.bin"))?;
        assert_eq!(bin, b"binary-data");
        Ok(())
    }
}
