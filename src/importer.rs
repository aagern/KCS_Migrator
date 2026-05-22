//! # Overview
//!
//! Replay side of the migrator. [`import_bundle`] reads an
//! [`crate::export`]-produced bundle directory and POSTs/PUTs every
//! resource onto a target KCS in a fixed dependency order so that
//! cross-resource references can be rewritten as new IDs are minted.
//!
//! Pipeline order (each step is its own private helper):
//!
//! 1. `reports-storage` config
//! 2. `scanner-priority`
//! 3. `LDAP` integration
//! 4. `SSO` integration
//! 5. `LLM` integration
//! 6. Image registries        (registers IDs, graceful-skips HTTP 400)
//! 7. Agent groups            (registers IDs, graceful-skips HTTP 400)
//! 8. Scanner policies        (registers IDs, enables if active)
//! 9. Assurance policies      (registers IDs, enables if active)
//! 10. Runtime profiles       (registers IDs)
//! 11. Runtime policies       (rewrites `runtimeProfileId` via mapper)
//! 12. Notifications warning  (cannot be replayed; emits operator notice)
//! 13. Response policies      (rewrites `notificationSettingsIds`)
//! 14. Network reputation     (binary blob upload)
//!
//! Some resources cannot be replayed even with a complete body — image
//! registries with credential-based auth, agent groups with a
//! server-issued `deploymentToken`. Those steps catch HTTP 400, emit
//! an `OPERATOR ACTION REQUIRED` warning naming the resource, and
//! continue. All other failures abort the import to preserve the
//! strict-error contract for genuine bugs.

use crate::client::KcsClient;
use crate::id_mapper::IdMapper;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::path::Path;

/// Field names that are always stripped before re-POSTing a resource.
/// These are either server-issued (`id`, `createdAt`, `updatedAt`,
/// `createdBy`, `deploymentToken`) or status snapshots
/// (`lastChecked`, `status`, `message`) that would either be rejected
/// by the target API or overwrite the target's own state.
const STRIP_FIELDS: &[&str] = &[
    "id",
    "createdAt",
    "updatedAt",
    "createdBy",
    "lastChecked",
    "status",
    "message",
    "deploymentToken",
];

/// Returns a copy of `body` with [`STRIP_FIELDS`] removed and any
/// `null`-valued fields dropped (some KCS endpoints reject explicit
/// nulls). Non-object inputs return an empty object.
fn strip(body: &Value) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(obj) = body.as_object() {
        for (k, v) in obj {
            if !STRIP_FIELDS.contains(&k.as_str()) && !v.is_null() {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    Value::Object(out)
}

/// Reads `path` and parses it as JSON. Errors include both I/O and
/// parse failures.
fn read_json(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

/// Extracts the HTTP status code from an [`anyhow::Error`] originating
/// in [`reqwest`], or returns `None` if the error is not a
/// [`reqwest::Error`] or has no associated status. Used to detect the
/// 400 graceful-skip cases in [`import_image_registries`] and
/// [`import_agent_groups`].
fn http_status(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<reqwest::Error>()
        .and_then(|re| re.status())
        .map(|s| s.as_u16())
}

/// Reads `result["id"]` as a string. The target server always returns
/// an `id`; defaulting to `""` keeps the function infallible for the
/// happy-path call sites that immediately register the value.
fn tgt_id_from(result: &Value) -> String {
    result["id"].as_str().unwrap_or("").to_string()
}

/// Reads `item["id"]` as a string. Bundle items always carry an `id`
/// from the source instance; defaulting to `""` keeps the function
/// infallible for the call sites that use it as a mapper key.
fn src_id_from(item: &Value) -> String {
    item["id"].as_str().unwrap_or("").to_string()
}

/// Returns `item[name_field]` as `&str`, falling back to `fallback`
/// (typically the source ID) if the field is absent or non-string.
/// Used to produce human-readable error and warning messages.
fn name_or_id<'a>(item: &'a Value, name_field: &str, fallback: &'a str) -> &'a str {
    item.get(name_field)
        .and_then(|n| n.as_str())
        .unwrap_or(fallback)
}

/// Calls `POST <endpoint>/<tgt_id>/enable` with an empty body. KCS
/// uses this pattern for the four policy classes (scanner, assurance,
/// runtime, response) that track an `enabled` boolean separately from
/// the resource definition itself.
async fn enable_policy(client: &KcsClient, endpoint: &str, tgt_id: &str) -> Result<()> {
    client
        .post(&format!("{endpoint}/{tgt_id}/enable"), &json!({}))
        .await?;
    Ok(())
}

/// Replays the reports-storage configuration via
/// `PUT /v1/reports/storage/config`. No-op if the bundle file is empty
/// (the source instance never configured it).
async fn import_reports_storage(client: &KcsClient, bundle: &Path) -> Result<()> {
    let cfg = read_json(&bundle.join("config/reports-storage.json"))?;
    if cfg.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        client.put_json("/v1/reports/storage/config", &cfg).await?;
    }
    Ok(())
}

/// Replays the scanner-priority configuration via
/// `POST /v1/scanners/priority`. No-op if the bundle file contains no
/// `controls` entries.
async fn import_scanner_priority(client: &KcsClient, bundle: &Path) -> Result<()> {
    let priority = read_json(&bundle.join("components/scanner-priority.json"))?;
    let has_controls = priority
        .get("controls")
        .and_then(|c| c.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if has_controls {
        client.post("/v1/scanners/priority", &priority).await?;
    }
    Ok(())
}

/// Replays the LDAP integration via `PUT /v1/integrations/ldap`. The
/// bundle stores LDAP as a single-element array (list endpoint) or a
/// single object; both shapes are accepted. No-op if empty.
async fn import_ldap(client: &KcsClient, bundle: &Path) -> Result<()> {
    let raw = read_json(&bundle.join("integrations/ldap.json"))?;
    let data = match raw.as_array() {
        Some(arr) => arr
            .first()
            .cloned()
            .unwrap_or(Value::Object(Default::default())),
        None => raw,
    };
    if data.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        client
            .put_json("/v1/integrations/ldap", &strip(&data))
            .await?;
    }
    Ok(())
}

/// Replays the SSO integration via `POST /v1/integrations/sso`.
/// No-op if the bundle file has no `clientId` (used as a "configured"
/// sentinel since the export endpoint returns `{}` when unset).
async fn import_sso(client: &KcsClient, bundle: &Path) -> Result<()> {
    let sso = read_json(&bundle.join("integrations/sso.json"))?;
    if sso.get("clientId").is_some() {
        client.post("/v1/integrations/sso", &strip(&sso)).await?;
    }
    Ok(())
}

/// Replays the LLM integration via `POST /v1/integrations/llm`.
/// No-op if the bundle file has no `type` field.
async fn import_llm(client: &KcsClient, bundle: &Path) -> Result<()> {
    let llm = read_json(&bundle.join("integrations/llm.json"))?;
    if llm.get("type").is_some() {
        client.post("/v1/integrations/llm", &strip(&llm)).await?;
    }
    Ok(())
}

/// Replays image registries via `POST /v1/integrations/image-registries`.
/// On success, records each `source_id → target_id` under resource
/// type `"image-registry"` in `mapper`.
///
/// Registries that use credential-based auth (`user_password`,
/// `service_account`, etc.) cannot be re-created automatically because
/// the API validates credentials at create time against the real
/// registry, and the export contains no passwords. Those POSTs return
/// HTTP 400 — we emit an `OPERATOR ACTION REQUIRED` warning naming the
/// registry and continue with the next entry rather than aborting.
///
/// # Errors
///
/// Any non-400 failure aborts the whole import.
async fn import_image_registries(
    client: &KcsClient,
    bundle: &Path,
    mapper: &mut IdMapper,
) -> Result<()> {
    let registries = read_json(&bundle.join("integrations/image-registries.json"))?;
    let arr = match registries.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for reg in &arr {
        let src_id = src_id_from(reg);
        let name = name_or_id(reg, "registryName", &src_id).to_string();
        match client
            .post("/v1/integrations/image-registries", &strip(reg))
            .await
        {
            Ok(result) => {
                mapper.register("image-registry", &src_id, &tgt_id_from(&result));
            }
            Err(e) if http_status(&e) == Some(400) => {
                eprintln!(
                    "OPERATOR ACTION REQUIRED: image registry '{name}' was not imported \
                     (HTTP 400). This usually means credentials are required but absent \
                     from the bundle. Recreate it manually in the target UI."
                );
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Replays agent groups via `POST /v1/integrations/agent-group`. On
/// success, registers each `source_id → target_id` under resource type
/// `"agent-group"` in `mapper`.
///
/// Agent groups are tied to a live cluster via a server-issued
/// `deploymentToken` — replay of a previously-deployed group typically
/// returns HTTP 400. We emit an `OPERATOR ACTION REQUIRED` warning and
/// continue, same as for credential-based image registries.
///
/// # Errors
///
/// Any non-400 failure aborts the whole import.
async fn import_agent_groups(
    client: &KcsClient,
    bundle: &Path,
    mapper: &mut IdMapper,
) -> Result<()> {
    let groups = read_json(&bundle.join("integrations/agent-groups.json"))?;
    let arr = match groups.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for group in &arr {
        let src_id = src_id_from(group);
        let name = name_or_id(group, "groupName", &src_id).to_string();
        match client
            .post("/v1/integrations/agent-group", &strip(group))
            .await
        {
            Ok(result) => {
                mapper.register("agent-group", &src_id, &tgt_id_from(&result));
            }
            Err(e) if http_status(&e) == Some(400) => {
                eprintln!(
                    "OPERATOR ACTION REQUIRED: agent group '{name}' was not imported \
                     (HTTP 400). Agent groups are tied to a live cluster and use a \
                     server-issued deployment token — recreate in the target UI."
                );
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Replays a "simple" policy collection — one that needs no FK
/// rewriting, just create + optional enable. Used for scanner and
/// assurance policies, which share the same shape.
///
/// For each entry in `file_rel`: `POST endpoint` with the stripped
/// body, register `(resource_type, src_id) → tgt_id` in `mapper`, and
/// if the source had `enabled = true`, also `POST endpoint/<tgt_id>/enable`.
///
/// # Errors
///
/// Any POST failure (create or enable) aborts the whole import.
async fn import_simple_policy_collection(
    client: &KcsClient,
    bundle: &Path,
    file_rel: &str,
    endpoint: &str,
    resource_type: &str,
    mapper: &mut IdMapper,
) -> Result<()> {
    let policies = read_json(&bundle.join(file_rel))?;
    let arr = match policies.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for pol in &arr {
        let src_id = src_id_from(pol);
        let enabled = pol["enabled"].as_bool().unwrap_or(false);
        let result = client.post(endpoint, &strip(pol)).await?;
        let tgt_id = tgt_id_from(&result);
        mapper.register(resource_type, &src_id, &tgt_id);
        if enabled {
            enable_policy(client, endpoint, &tgt_id).await?;
        }
    }
    Ok(())
}

/// Replays runtime profiles via `POST /v1/policies/runtime-profile`.
/// Must run before [`import_runtime_policies`], because runtime
/// policies reference runtime-profile IDs that the mapper rewrites
/// using the registrations made here.
///
/// # Errors
///
/// Any POST failure aborts the import.
async fn import_runtime_profiles(
    client: &KcsClient,
    bundle: &Path,
    mapper: &mut IdMapper,
) -> Result<()> {
    let profiles = read_json(&bundle.join("policies/runtime-profiles.json"))?;
    let arr = match profiles.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for profile in &arr {
        let src_id = src_id_from(profile);
        let result = client
            .post("/v1/policies/runtime-profile", &strip(profile))
            .await?;
        mapper.register("runtime-profile", &src_id, &tgt_id_from(&result));
    }
    Ok(())
}

/// Replays runtime policies via `POST /v1/policies/runtime`. Each
/// policy's `runtimeProfileMatchBlocks[*].runtimeProfileId` is
/// rewritten from the source instance's ID space to the target's via
/// `mapper` before the POST; see
/// [`rewrite_runtime_profile_match_blocks`].
///
/// # Errors
///
/// Aborts the import if any referenced runtime-profile ID was not
/// registered earlier (typical cause: the profile was deleted on the
/// source between export and import), or if any POST fails.
async fn import_runtime_policies(
    client: &KcsClient,
    bundle: &Path,
    mapper: &mut IdMapper,
) -> Result<()> {
    let policies = read_json(&bundle.join("policies/runtime.json"))?;
    let arr = match policies.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for pol in &arr {
        let src_id = src_id_from(pol);
        let enabled = pol["enabled"].as_bool().unwrap_or(false);
        let mut body = strip(pol);
        rewrite_runtime_profile_match_blocks(&mut body, pol, &src_id, mapper)?;
        let result = client.post("/v1/policies/runtime", &body).await?;
        let tgt_id = tgt_id_from(&result);
        mapper.register("runtime-policy", &src_id, &tgt_id);
        if enabled {
            enable_policy(client, "/v1/policies/runtime", &tgt_id).await?;
        }
    }
    Ok(())
}

/// Rewrites the `runtimeProfileMatchBlocks` array on a runtime-policy
/// body so that each block's `runtimeProfileId` is the target
/// instance's ID instead of the source's.
///
/// `original` is the pre-strip body; it's only used to recover the
/// policy `name` for the error message.
///
/// # Errors
///
/// Returns an error if any `runtimeProfileId` referenced by a block
/// was not previously registered in `mapper`. The importer hard-aborts
/// on this — a missing FK indicates the source bundle is internally
/// inconsistent.
fn rewrite_runtime_profile_match_blocks(
    body: &mut Value,
    original: &Value,
    src_id: &str,
    mapper: &IdMapper,
) -> Result<()> {
    let Some(blocks) = body
        .get("runtimeProfileMatchBlocks")
        .and_then(|b| b.as_array())
        .cloned()
    else {
        return Ok(());
    };

    let mut rewritten = Vec::with_capacity(blocks.len());
    for mut block in blocks {
        if let Some(old_id) = block.get("runtimeProfileId").and_then(|v| v.as_str()) {
            let new_id = mapper.resolve("runtime-profile", old_id).map_err(|_| {
                anyhow!(
                    "Runtime policy '{}' references runtime profile ID '{}' \
                     that was not registered during import.",
                    name_or_id(original, "name", src_id),
                    old_id
                )
            })?;
            block["runtimeProfileId"] = Value::String(new_id.to_string());
        }
        rewritten.push(block);
    }
    body["runtimeProfileMatchBlocks"] = Value::Array(rewritten);
    Ok(())
}

/// Reads the notifications-REFERENCE bundle file (which lists email,
/// telegram, and webhook channels exported for reference only) and
/// emits a single `OPERATOR ACTION REQUIRED` warning summarizing how
/// many channels need to be recreated by hand.
///
/// Notification channels cannot be replayed automatically because the
/// KCS API has no create endpoint for them.
fn warn_notifications_reference(bundle: &Path) -> Result<()> {
    let notif_ref = read_json(&bundle.join("integrations/notifications-REFERENCE.json"))?;
    let count = |key: &str| notif_ref[key].as_array().map(|a| a.len()).unwrap_or(0);
    let email = count("email");
    let telegram = count("telegram");
    let webhook = count("webhook");
    if email + telegram + webhook > 0 {
        eprintln!(
            "OPERATOR ACTION REQUIRED: Notification channels cannot be imported automatically.\n\
             Please manually recreate:\n  email: {email}\n  telegram: {telegram}\n  webhook: {webhook}"
        );
    }
    Ok(())
}

/// Replays response policies via `POST /v1/policies/response`. Each
/// policy's `notificationSettingsIds` is rewritten from the source's
/// ID space to the target's via `mapper`; see
/// [`rewrite_notification_settings_ids`].
///
/// # Errors
///
/// Aborts the import if any notification ID referenced by a response
/// policy was not previously registered. Since notification channels
/// cannot be auto-imported, the operator must seed `mapper` manually
/// (or run with an empty `notificationSettingsIds` field) before
/// reaching this step.
async fn import_response_policies(
    client: &KcsClient,
    bundle: &Path,
    mapper: &mut IdMapper,
) -> Result<()> {
    let policies = read_json(&bundle.join("policies/response.json"))?;
    let arr = match policies.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for pol in &arr {
        let src_id = src_id_from(pol);
        let enabled = pol["enabled"].as_bool().unwrap_or(false);
        let mut body = strip(pol);
        rewrite_notification_settings_ids(&mut body, pol, &src_id, mapper)?;
        let result = client.post("/v1/policies/response", &body).await?;
        let tgt_id = tgt_id_from(&result);
        mapper.register("response-policy", &src_id, &tgt_id);
        if enabled {
            enable_policy(client, "/v1/policies/response", &tgt_id).await?;
        }
    }
    Ok(())
}

/// Rewrites the `notificationSettingsIds` array on a response-policy
/// body so each ID is the target instance's ID. `original` is used
/// only to recover the policy name for the error message.
///
/// # Errors
///
/// Returns an error listing every unmapped notification ID. The
/// importer aborts on this — silently dropping notifications would
/// produce a policy that fires correctly but notifies no one.
fn rewrite_notification_settings_ids(
    body: &mut Value,
    original: &Value,
    src_id: &str,
    mapper: &IdMapper,
) -> Result<()> {
    let Some(notif_ids) = body
        .get("notificationSettingsIds")
        .and_then(|v| v.as_array())
        .cloned()
    else {
        return Ok(());
    };

    let mut mapped = Vec::with_capacity(notif_ids.len());
    let mut unmapped = Vec::new();
    for id_val in &notif_ids {
        if let Some(id) = id_val.as_str() {
            match mapper.resolve("notification", id) {
                Ok(new_id) => mapped.push(Value::String(new_id.to_string())),
                Err(_) => unmapped.push(id.to_string()),
            }
        }
    }
    if !unmapped.is_empty() {
        return Err(anyhow!(
            "Cannot import response policy '{}': notification channel IDs are not mapped — {:?}",
            name_or_id(original, "name", src_id),
            unmapped
        ));
    }
    body["notificationSettingsIds"] = Value::Array(mapped);
    Ok(())
}

/// Uploads the network-reputation binary blob via
/// `PUT /v1/policies/custom-reputation/import`. No-op if the bundle
/// file is missing or empty.
async fn import_network_reputation(client: &KcsClient, bundle: &Path) -> Result<()> {
    let path = bundle.join("policies/network-reputation.bin");
    if !path.exists() {
        return Ok(());
    }
    let data = std::fs::read(&path)?;
    if data.is_empty() {
        return Ok(());
    }
    client
        .put_bytes("/v1/policies/custom-reputation/import", data)
        .await?;
    Ok(())
}

/// # Overview
///
/// Replays a bundle directory produced by [`crate::export::export_all`]
/// onto the target KCS reached via `client`. Resources are replayed in
/// the dependency order documented at the top of this module; FK
/// fields on downstream resources are rewritten as new IDs are minted.
///
/// Returns the populated [`IdMapper`] so callers (or tests) can
/// inspect the source→target ID mappings that were made.
///
/// # Errors
///
/// Returns the first hard error encountered. "Graceful skip" cases
/// (HTTP 400 on image registries or agent groups, missing
/// notifications-REFERENCE file) emit `OPERATOR ACTION REQUIRED`
/// warnings to stderr and do not abort.
///
/// # Examples
///
/// ```no_run
/// use kcs_migrator::client::KcsClient;
/// use kcs_migrator::importer;
/// use std::path::Path;
///
/// # async fn run() -> anyhow::Result<()> {
/// let client = KcsClient::new("https://kcs.tgt.corp", "tok", true, None)?;
/// let mapper = importer::import_bundle(&client, Path::new("kcs-export-…")).await?;
/// # let _ = mapper;
/// # Ok(()) }
/// ```
pub async fn import_bundle(client: &KcsClient, bundle: &Path) -> Result<IdMapper> {
    let mut mapper = IdMapper::new();

    import_reports_storage(client, bundle).await?;
    import_scanner_priority(client, bundle).await?;
    import_ldap(client, bundle).await?;
    import_sso(client, bundle).await?;
    import_llm(client, bundle).await?;
    import_image_registries(client, bundle, &mut mapper).await?;
    import_agent_groups(client, bundle, &mut mapper).await?;
    import_simple_policy_collection(
        client,
        bundle,
        "policies/scanner.json",
        "/v1/policies/scanner",
        "scanner-policy",
        &mut mapper,
    )
    .await?;
    import_simple_policy_collection(
        client,
        bundle,
        "policies/assurance.json",
        "/v1/policies/assurance",
        "assurance-policy",
        &mut mapper,
    )
    .await?;
    import_runtime_profiles(client, bundle, &mut mapper).await?;
    import_runtime_policies(client, bundle, &mut mapper).await?;
    warn_notifications_reference(bundle)?;
    import_response_policies(client, bundle, &mut mapper).await?;
    import_network_reputation(client, bundle).await?;

    Ok(mapper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_bundle(tmp: &tempfile::TempDir) -> Result<std::path::PathBuf> {
        let bundle = tmp.path().join("kcs-export-2026-01-01_00-00-00");
        std::fs::create_dir_all(bundle.join("integrations"))?;
        std::fs::create_dir_all(bundle.join("policies"))?;
        std::fs::create_dir_all(bundle.join("components"))?;
        std::fs::create_dir_all(bundle.join("config"))?;

        let write = |rel: &str, val: &Value| -> Result<()> {
            std::fs::write(bundle.join(rel), serde_json::to_string(val)?)?;
            Ok(())
        };

        write("manifest.json", &json!({"tool_version": "0.1.0"}))?;
        write("integrations/image-registries.json", &json!([]))?;
        write("integrations/ldap.json", &json!([]))?;
        write("integrations/sso.json", &json!({}))?;
        write("integrations/llm.json", &json!({}))?;
        write("integrations/agent-groups.json", &json!([]))?;
        write(
            "integrations/notifications-REFERENCE.json",
            &json!({"email":[],"telegram":[],"webhook":[]}),
        )?;
        write("policies/scanner.json", &json!([]))?;
        write("policies/assurance.json", &json!([]))?;
        write("policies/runtime-profiles.json", &json!([]))?;
        write("policies/runtime.json", &json!([]))?;
        write("policies/response.json", &json!([]))?;
        write("components/scanner-priority.json", &json!({}))?;
        write("config/reports-storage.json", &json!({}))?;

        Ok(bundle)
    }

    #[tokio::test]
    async fn import_scanner_policy_creates_and_enables() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/scanner.json"),
            serde_json::to_string(&json!([
                {"id": "pol-src-1", "name": "My Scanner", "enabled": true, "useMalware": true}
            ]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/scanner"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "pol-tgt-99"})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/scanner/pol-tgt-99/enable"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let mapper = import_bundle(&client, &bundle).await?;
        assert_eq!(mapper.resolve("scanner-policy", "pol-src-1")?, "pol-tgt-99");
        Ok(())
    }

    #[tokio::test]
    async fn import_runtime_policy_rewrites_profile_ids() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/runtime-profiles.json"),
            serde_json::to_string(&json!([{"id": "rp-src-1", "name": "Profile A"}]))?,
        )?;
        std::fs::write(
            bundle.join("policies/runtime.json"),
            serde_json::to_string(&json!([{
                "id": "rt-src-1", "name": "Runtime Policy", "enabled": false,
                "runtimeProfileMatchBlocks": [{"runtimeProfileId": "rp-src-1", "namespacePattern": "*"}]
            }]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/runtime-profile"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "rp-tgt-1"})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/runtime"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "rt-tgt-1"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let mapper = import_bundle(&client, &bundle).await?;
        assert_eq!(mapper.resolve("runtime-profile", "rp-src-1")?, "rp-tgt-1");
        assert_eq!(mapper.resolve("runtime-policy", "rt-src-1")?, "rt-tgt-1");
        Ok(())
    }

    #[tokio::test]
    async fn import_runtime_policy_errors_on_unmapped_profile() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/runtime.json"),
            serde_json::to_string(&json!([{
                "id": "rt-src-1", "name": "Broken", "enabled": false,
                "runtimeProfileMatchBlocks": [{"runtimeProfileId": "rp-ghost-99"}]
            }]))?,
        )?;

        let server = MockServer::start().await;
        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let err = import_bundle(&client, &bundle).await.unwrap_err();
        assert!(err.to_string().contains("rp-ghost-99"));
        Ok(())
    }

    #[tokio::test]
    async fn import_response_policy_errors_on_unmapped_notification() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/response.json"),
            serde_json::to_string(&json!([{
                "id": "resp-src-1", "name": "Alert Policy", "enabled": false,
                "notificationSettingsIds": ["notif-unknown-99"]
            }]))?,
        )?;

        let server = MockServer::start().await;
        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let err = import_bundle(&client, &bundle).await.unwrap_err();
        assert!(err.to_string().contains("notif-unknown-99"));
        Ok(())
    }

    #[tokio::test]
    async fn import_network_reputation_uploads_binary() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        let binary = b"\x00\x01\x02\xde\xad\xbe\xef";
        std::fs::write(bundle.join("policies/network-reputation.bin"), binary)?;

        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/policies/custom-reputation/import"))
            .and(header("content-type", "application/octet-stream"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        import_bundle(&client, &bundle).await?;
        Ok(())
    }

    #[tokio::test]
    async fn import_continues_when_registry_post_returns_400() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("integrations/image-registries.json"),
            serde_json::to_string(&json!([
                {"id": "reg-cred-1", "registryName": "Creds Required", "authenticationType": "user_password", "registryType": "jfrog_artifactory", "scanTimeout": 60},
                {"id": "reg-public-1", "registryName": "Public", "authenticationType": "public", "registryType": "unknown", "scanTimeout": 60}
            ]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({"code": "MDW-305", "message": "incorrect username"})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(json!({"id": "reg-tgt-public"})),
            )
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let mapper = import_bundle(&client, &bundle).await?;
        assert!(mapper.resolve("image-registry", "reg-cred-1").is_err());
        assert_eq!(
            mapper.resolve("image-registry", "reg-public-1")?,
            "reg-tgt-public"
        );
        Ok(())
    }

    #[tokio::test]
    async fn import_strips_metadata_fields_before_post() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("integrations/image-registries.json"),
            serde_json::to_string(&json!([{
                "id": "reg-src-1", "name": "My Registry",
                "createdAt": "2024-01-01T00:00:00Z",
                "updatedAt": "2024-01-02T00:00:00Z",
                "lastChecked": "2024-01-03T00:00:00Z",
                "status": "active", "message": null,
                "apiUrl": "https://registry.example.com"
            }]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "reg-tgt-1"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let mapper = import_bundle(&client, &bundle).await?;
        assert_eq!(mapper.resolve("image-registry", "reg-src-1")?, "reg-tgt-1");
        Ok(())
    }
}
