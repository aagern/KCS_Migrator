//! # Overview
//!
//! Replay side of the migrator. [`import_bundle`] reads an
//! [`crate::export`]-produced bundle directory and POSTs/PUTs every
//! resource onto a target KCS in a fixed dependency order so that
//! cross-resource references can be rewritten as new IDs are minted.
//!
//! Pipeline order (each step is its own private helper). Dependencies
//! first: whatever owns an ID comes before whatever references it.
//!
//! ```text
//!  1  reports-storage config
//!  2  scanner priority
//!  3  security scopes            read-only; matches bundle scopes to the target by name
//!  4  LDAP                       POST + /{id}/enable
//!  5  SSO
//!  6  LLM
//!  7  SIEM integrations
//!  8  image registries           registers IDs; 400 -> skip + warn
//!  9  external scan groups
//! 10  agent groups               translated; registers IDs; 400 -> skip + warn
//! 11  benchmark controls         v3 only; CEL rules inlined from CEL/
//! 12  benchmark frameworks       v3 only; + /{id}/enable
//! 13  assurance controls         v3 only; CEL rules inlined
//! 14  scanner policies           + /{id}/enable
//! 15  assurance policies         translated; + /{id}/enable
//! 16  admission controls         v3 only; CEL rules inlined
//! 17  admission-controller policies   v3 only
//! 18  runtime profiles           translated; registers IDs
//! 19  runtime policies           rewrites runtimeProfileId; splits off an
//!                                admission policy when the bundle is `APIv1`
//! 20  notification channels      warning only, no create endpoint exists
//! 21  response policies          unmappable channels dropped + warned
//! 22  custom-reputation list selection
//! 23  network-reputation blob
//! ```
//!
//! Steps 11-13 and 16-17 are the resource classes KCS 2.5 introduced. On an
//! `APIv1` target they are skipped without a request, because 2.4 has no route
//! for them and a 404 would abort the import.
//!
//! Some resources cannot be replayed even with a complete body — image
//! registries with credential-based auth, agent groups with a
//! server-issued `deploymentToken`. Those steps catch HTTP 400, emit
//! an `OPERATOR ACTION REQUIRED` warning naming the resource, and
//! continue. All other failures abort the import to preserve the
//! strict-error contract for genuine bugs.

use crate::bundle::Manifest;
use crate::cel;
use crate::client::{error_status, KcsClient};
use crate::id_mapper::IdMapper;
use crate::translate::{Resource, Translator};
use crate::version::{ApiVersion, KcsVersion};
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

/// Whether a POST failed with the HTTP 400 that means "this resource
/// cannot be replayed", as opposed to a genuine error.
fn is_bad_request(e: &anyhow::Error) -> bool {
    error_status(e).is_some_and(|s| s == reqwest::StatusCode::BAD_REQUEST)
}

/// Reads the `id` the target assigned to a resource it just created.
///
/// Fallible on purpose. This used to default to `""`, which registered an
/// empty string as the target ID: every later foreign-key rewrite then
/// resolved to `""`, the POST was accepted, and the operator got policies
/// silently pointing at nothing. A created resource with no `id` is a
/// broken assumption about the API, so it stops the import and names the
/// resource.
///
/// # Errors
///
/// Returns an error when the response body has no string `id`.
fn tgt_id_from(result: &Value, what: &str) -> Result<String> {
    result
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            anyhow!(
                "the target accepted the {what} but returned no id, so later references \
                 to it cannot be rewritten. Response body: {result}"
            )
        })
}

/// Reads a bundle item's source `id`, or `None` when it has none.
///
/// Returns `Option` rather than defaulting to `""` for the same reason as
/// [`tgt_id_from`]: an empty mapper key collides with every other
/// id-less item. Unlike a missing target id this is not fatal — a bundle
/// written by 0.1.0 can contain truncated entries — so the caller skips
/// the item with a warning.
fn src_id_from(item: &Value) -> Option<String> {
    item.get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
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

/// Translates a body in place and reports what changed.
///
/// A rename is routine and goes out as a `Note`; a *dropped* field is not,
/// because it is configuration that existed on the source and will not
/// exist on the target. Saying so per resource is the only way an operator
/// can tell which policies to re-check by hand after a 2.4 to 2.5 move.
fn report_translation(
    translator: Translator,
    resource: Resource,
    body: &mut Value,
    kind: &str,
    name: &str,
) {
    let changes = translator.resource(resource, body);
    if !changes.dropped.is_empty() {
        eprintln!(
            "Note: {kind} '{name}': {:?} removed -- APIv3 has no equivalent field. \
             Check the resource on the target if it relied on them.",
            changes.dropped
        );
    }
}

/// Reports a bundle entry with no usable source `id` and tells the caller
/// to skip it.
///
/// Such an entry cannot be registered in the mapper — there is no key —
/// so anything referencing it later would be unresolvable. Skipping with a
/// warning beats inventing a key, which is what defaulting to `""` used to
/// do: every id-less entry collided on the same key and quietly overwrote
/// the previous one's mapping.
fn warn_skipped_without_id(kind: &str, item: &Value) {
    let label = item
        .get("name")
        .or_else(|| item.get("registryName"))
        .or_else(|| item.get("groupName"))
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    eprintln!(
        "Warning: skipping {kind} '{label}' from the bundle: it carries no source id, so \
         later references to it could not be rewritten."
    );
}

/// Reports `systemScopes` entries dropped during a remap.
fn warn_dropped_scopes(kind: &str, name: &str, dropped: &[String]) {
    if dropped.is_empty() {
        return;
    }
    eprintln!(
        "OPERATOR ACTION REQUIRED: {kind} '{name}' referenced {} security scope(s) that \
         do not exist on the target ({dropped:?}); they were removed from its scope list. \
         Set its scope in the target console.",
        dropped.len()
    );
}

/// Mapper resource type under which security scopes are registered.
const SCOPE_TYPE: &str = "scope";

/// # Overview
///
/// How an import should behave where it has a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImportOptions {
    /// Abort rather than continue when a response policy references a
    /// notification channel that cannot be mapped onto the target.
    ///
    /// Off by default, because the abort is unavoidable in normal use:
    /// notification channels have no create endpoint in either API
    /// generation, so the mapper is *never* populated for them and any
    /// response policy wired to a channel would stop the import.
    pub strict_notifications: bool,

    /// The target instance's release, when it was detected.
    ///
    /// Used only to name both sides when a downgrade is refused. Carried
    /// here rather than on [`KcsClient`] because a client built with an
    /// explicit `--api-version` never probed and so has no release to
    /// report, and widening the client with a field that is sometimes
    /// absent would push that `Option` into every call site.
    pub target_kcs: Option<KcsVersion>,
}

/// Builds the source-ID → target-ID mapping for security scopes.
///
/// Scopes cannot be created through the API — `/security/scopes` is
/// GET-only — so they are matched by **name**: the bundle's
/// `security/scopes-REFERENCE.json` gives each source scope's name, the
/// target's own scope list gives the ID that name has there.
///
/// Four resource classes reference scopes by ID in `systemScopes`.
/// Without this step those IDs stay in the source instance's ID space,
/// and the target accepts them — scoping the policy to nothing that
/// exists, with no error anywhere.
///
/// A bundle with no scopes file (every bundle written by 0.1.0) registers
/// nothing and is not an error; the remap step then leaves `systemScopes`
/// alone rather than clearing it.
///
/// # Errors
///
/// Returns an error if the target's scope list cannot be read.
async fn register_security_scopes(
    client: &KcsClient,
    bundle: &Path,
    mapper: &mut IdMapper,
) -> Result<()> {
    let path = bundle.join("security/scopes-REFERENCE.json");
    if !path.exists() {
        eprintln!(
            "Note: this bundle carries no security/scopes-REFERENCE.json, so scope \
             references are replayed unchanged. Check every policy's scope on the target."
        );
        return Ok(());
    }

    let bundle_scopes = read_json(&path)?;
    let target_scopes = client.get("/security/scopes").await?;

    // Mark the class considered before matching anything. A bundle that lists its
    // scopes but matches none of them must still have its stale IDs dropped, and
    // that is indistinguishable from "no scope file" by map contents alone.
    mapper.declare_type(SCOPE_TYPE);

    // name -> target id
    let mut by_name: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for scope in target_scopes.as_array().unwrap_or(&Vec::new()) {
        if let (Some(name), Some(id)) = (
            scope.get("name").and_then(Value::as_str),
            scope.get("id").and_then(Value::as_str),
        ) {
            by_name.insert(name.to_string(), id.to_string());
        }
    }

    let mut unmatched = Vec::new();
    for scope in bundle_scopes.as_array().unwrap_or(&Vec::new()) {
        let (Some(src_id), Some(name)) = (
            scope.get("id").and_then(Value::as_str),
            scope.get("name").and_then(Value::as_str),
        ) else {
            continue;
        };
        match by_name.get(name) {
            Some(tgt_id) => mapper.register(SCOPE_TYPE, src_id, tgt_id),
            None => unmatched.push(name.to_string()),
        }
    }

    if !unmatched.is_empty() {
        eprintln!(
            "OPERATOR ACTION REQUIRED: these security scopes exist in the bundle but not \
             on the target, and cannot be created through the API: {unmatched:?}. Create \
             them in the target console with the same names and re-run, or expect the \
             policies that referenced them to lose their scope."
        );
    }
    Ok(())
}

/// Rewrites a resource's `systemScopes` array into the target's ID space.
///
/// Returns the source IDs that had no counterpart; those are dropped from
/// the array rather than passed through, because a stale ID is accepted
/// by the target and silently scopes the policy to nothing.
///
/// No-op when no scope mappings were registered at all, which keeps a
/// 0.1.0 bundle's behaviour unchanged instead of emptying every array.
fn remap_system_scopes(body: &mut Value, mapper: &IdMapper) -> Vec<String> {
    if !mapper.has_type(SCOPE_TYPE) {
        return Vec::new();
    }
    let Some(scopes) = body.get("systemScopes").and_then(Value::as_array).cloned() else {
        return Vec::new();
    };

    let mut rewritten = Vec::with_capacity(scopes.len());
    let mut stale = Vec::new();
    for entry in &scopes {
        let Some(src_id) = entry.as_str() else {
            continue;
        };
        match mapper.resolve_opt(SCOPE_TYPE, src_id) {
            Some(tgt_id) => rewritten.push(Value::String(tgt_id.to_string())),
            None => stale.push(src_id.to_string()),
        }
    }

    if let Some(obj) = body.as_object_mut() {
        obj.insert("systemScopes".to_string(), Value::Array(rewritten));
    }
    stale
}

/// Replays a flat collection: read the file, optionally inline CEL rules,
/// translate, remap scopes, POST each entry, register the new ID.
///
/// Returns the number of entries created. Factored out because the six
/// resources added for KCS 2.5 differ only in their file, endpoint and
/// mapper key — writing six near-identical loops is how the LDAP and
/// scope bugs got in, each a copy that drifted from its neighbours.
///
/// # Errors
///
/// Any POST failure aborts the import, except the 404 that means the
/// target does not serve this resource at all.
async fn import_collection(
    client: &KcsClient,
    bundle: &Path,
    collection: &PolicyCollection<'_>,
    mapper: &mut IdMapper,
    translator: Translator,
) -> Result<usize> {
    let PolicyCollection {
        file_rel,
        endpoint,
        resource_type,
        resource,
        has_cel,
        graceful_400,
    } = *collection;

    let path = bundle.join(file_rel);
    if !path.exists() {
        // A format-1 bundle has none of these files. Their absence is not an
        // error; it means the source predates the resource.
        return Ok(0);
    }
    let mut items = read_json(&path)?;
    if has_cel {
        // Must happen before the POST: the API wants the rule inline, and the
        // bundle stores it as a pointer to an editable .cel file.
        cel::inline(&mut items, bundle)?;
    }

    let Some(arr) = items.as_array().cloned() else {
        return Ok(0);
    };
    let mut created = 0;

    for item in &arr {
        let Some(src_id) = src_id_from(item) else {
            warn_skipped_without_id(resource_type, item);
            continue;
        };
        let name = name_or_id(item, "name", &src_id).to_string();
        let enabled = item["enabled"].as_bool().unwrap_or(false);

        let mut body = strip(item);
        report_translation(translator, resource, &mut body, resource_type, &name);
        let unscoped = remap_system_scopes(&mut body, mapper);
        warn_dropped_scopes(resource_type, &name, &unscoped);

        match client.post(endpoint, &body).await {
            Ok(result) => {
                let tgt_id = tgt_id_from(&result, &format!("{resource_type} '{name}'"))?;
                mapper.register(resource_type, &src_id, &tgt_id);
                created += 1;
                if enabled {
                    enable_policy(client, endpoint, &tgt_id).await?;
                }
            }
            // Same contract as image registries, where it applies: a 400 means
            // this one entry cannot be replayed, not that the import is broken.
            Err(e) if graceful_400 && is_bad_request(&e) => {
                eprintln!(
                    "OPERATOR ACTION REQUIRED: {resource_type} '{name}' was not imported \
                     (HTTP 400). Recreate it in the target console."
                );
            }
            Err(e) => return Err(e),
        }
    }
    Ok(created)
}

/// Replays the KCS 2.5 resource classes, or reports them skipped.
///
/// An `APIv1` target has no route for any of these, and a 404 is not a
/// graceful-skip status, so attempting one would abort the whole import.
/// The entries stay in the bundle either way.
async fn import_or_skip_v3_only(
    client: &KcsClient,
    bundle: &Path,
    group: &[PolicyCollection<'_>],
    mapper: &mut IdMapper,
    translator: Translator,
    target_is_v3: bool,
) -> Result<()> {
    for collection in group {
        if target_is_v3 {
            import_collection(client, bundle, collection, mapper, translator).await?;
        } else {
            note_v3_only_skip(
                collection.resource_type,
                count_entries(bundle, collection.file_rel),
            );
        }
    }
    Ok(())
}

/// Reports a v3-only resource class skipped because the target is `APIv1`.
fn note_v3_only_skip(kind: &str, count: usize) {
    if count == 0 {
        return;
    }
    eprintln!(
        "Note: skipping {count} {kind} — this target speaks APIv1 (KCS 2.4 or earlier), \
         which has no equivalent resource. They remain in the bundle."
    );
}

/// Counts the entries in a bundle collection file, for the skip notice.
fn count_entries(bundle: &Path, file_rel: &str) -> usize {
    read_json(&bundle.join(file_rel))
        .ok()
        .as_ref()
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

/// Replays the custom-reputation list selection via
/// `POST /policies/custom-reputation/toggle`.
///
/// The list's entries ride in the binary blob; this restores which list is
/// active, which the blob does not carry. No-op when the bundle recorded
/// no selection.
async fn import_custom_reputation_toggle(client: &KcsClient, bundle: &Path) -> Result<()> {
    let path = bundle.join("policies/custom-reputation.json");
    if !path.exists() {
        return Ok(());
    }
    let state = read_json(&path)?;
    let Some(enabled_list) = state.get("enabledList").and_then(Value::as_str) else {
        return Ok(());
    };
    client
        .post(
            "/policies/custom-reputation/toggle",
            &json!({ "enabledList": enabled_list }),
        )
        .await?;
    Ok(())
}

/// Replays the reports-storage configuration via
/// `PUT /reports/storage/config`. No-op if the bundle file is empty
/// (the source instance never configured it).
async fn import_reports_storage(client: &KcsClient, bundle: &Path) -> Result<()> {
    let cfg = read_json(&bundle.join("config/reports-storage.json"))?;
    if cfg.as_object().is_some_and(|o| !o.is_empty()) {
        client.put_json("/reports/storage/config", &cfg).await?;
    }
    Ok(())
}

/// Replays the scanner-priority configuration via
/// `POST /scanners/priority`. No-op if the bundle file contains no
/// `controls` entries.
async fn import_scanner_priority(client: &KcsClient, bundle: &Path) -> Result<()> {
    let priority = read_json(&bundle.join("components/scanner-priority.json"))?;
    let has_controls = priority
        .get("controls")
        .and_then(|c| c.as_array())
        .is_some_and(|a| !a.is_empty());
    if has_controls {
        client.post("/scanners/priority", &priority).await?;
    }
    Ok(())
}

/// Replays LDAP integrations via `POST /integrations/ldap`, then
/// `POST /integrations/ldap/<id>/enable` for each one the source had
/// enabled.
///
/// This used to send `PUT /integrations/ldap`, a route that does not
/// exist on either generation — verified live, `404 page not found` on
/// both `/api/v1/` and `/api/v3/`. The `OpenAPI` documents agree:
/// `/integrations/ldap` is `GET|POST|DELETE`, and `PUT` lives on
/// `/integrations/ldap/{id}`. Because 404 is not one of the
/// graceful-skip statuses, any source with LDAP configured aborted the
/// entire import at step 4 — before policies, registries or anything
/// else had been replayed.
///
/// LDAP is a list resource, so the bundle's array is replayed entry by
/// entry. A bundle written by 0.1.0 may hold a bare object instead; that
/// shape is still accepted.
///
/// # Errors
///
/// Any POST failure aborts the import.
async fn import_ldap(client: &KcsClient, bundle: &Path, mapper: &mut IdMapper) -> Result<()> {
    let raw = read_json(&bundle.join("integrations/ldap.json"))?;
    // Normalise both shapes to a list: `[{...}]` from the list endpoint, or a
    // bare `{...}` from a 0.1.0-era bundle.
    let entries = match &raw {
        Value::Array(items) => items.clone(),
        Value::Object(obj) if !obj.is_empty() => vec![raw.clone()],
        _ => return Ok(()),
    };

    for entry in &entries {
        if entry.as_object().is_none_or(serde_json::Map::is_empty) {
            continue;
        }
        let src_id = src_id_from(entry);
        let label = src_id.as_deref().unwrap_or("<no id>");
        let enabled = entry["enabled"].as_bool().unwrap_or(false);

        let result = client.post("/integrations/ldap", &strip(entry)).await?;
        let tgt_id = tgt_id_from(&result, &format!("LDAP integration '{label}'"))?;
        if let Some(src_id) = src_id {
            mapper.register("ldap", &src_id, &tgt_id);
        }

        if enabled {
            // A separate endpoint from the create, same as the policy classes.
            // Skipping it left the integration present but switched off, which
            // looks like a successful migration and authenticates nobody.
            client
                .post(&format!("/integrations/ldap/{tgt_id}/enable"), &json!({}))
                .await?;
        }
    }
    Ok(())
}

/// Replays the SSO integration via `POST /integrations/sso`.
/// No-op if the bundle file has no `clientId` (used as a "configured"
/// sentinel since the export endpoint returns `{}` when unset).
async fn import_sso(client: &KcsClient, bundle: &Path) -> Result<()> {
    let sso = read_json(&bundle.join("integrations/sso.json"))?;
    if sso.get("clientId").is_some() {
        client.post("/integrations/sso", &strip(&sso)).await?;
    }
    Ok(())
}

/// Replays the LLM integration via `POST /integrations/llm`.
/// No-op if the bundle file has no `type` field.
async fn import_llm(client: &KcsClient, bundle: &Path) -> Result<()> {
    let llm = read_json(&bundle.join("integrations/llm.json"))?;
    if llm.get("type").is_some() {
        client.post("/integrations/llm", &strip(&llm)).await?;
    }
    Ok(())
}

/// Replays image registries via `POST /integrations/image-registries`.
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
        let Some(src_id) = src_id_from(reg) else {
            warn_skipped_without_id("image registry", reg);
            continue;
        };
        let name = name_or_id(reg, "registryName", &src_id).to_string();
        match client
            .post("/integrations/image-registries", &strip(reg))
            .await
        {
            Ok(result) => {
                let tgt_id = tgt_id_from(&result, &format!("image registry '{name}'"))?;
                mapper.register("image-registry", &src_id, &tgt_id);
            }
            Err(e) if is_bad_request(&e) => {
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

/// Replays agent groups via `POST /integrations/agent-group`. On
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
    translator: Translator,
) -> Result<()> {
    let groups = read_json(&bundle.join("integrations/agent-groups.json"))?;
    let arr = match groups.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for group in &arr {
        let Some(src_id) = src_id_from(group) else {
            warn_skipped_without_id("agent group", group);
            continue;
        };
        let name = name_or_id(group, "groupName", &src_id).to_string();
        let mut body = strip(group);
        report_translation(
            translator,
            Resource::AgentGroup,
            &mut body,
            "agent group",
            &name,
        );
        match client.post("/integrations/agent-group", &body).await {
            Ok(result) => {
                let tgt_id = tgt_id_from(&result, &format!("agent group '{name}'"))?;
                mapper.register("agent-group", &src_id, &tgt_id);
            }
            Err(e) if is_bad_request(&e) => {
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

/// Identifies one "simple" policy collection — one that needs no
/// foreign-key rewriting, just create plus an optional enable.
///
/// Grouped into a struct because passing these four alongside the client,
/// bundle, mapper and translator put the function at eight arguments,
/// which `clippy::too_many_arguments` flags and which is genuinely hard to
/// call correctly: `file_rel`, `endpoint` and `resource_type` are all
/// `&str`, so a transposed pair compiles and then writes the wrong
/// resource to the wrong endpoint.
///
/// The lifetime ties the three borrowed names to the caller's string
/// literals; nothing here owns them, because every call site passes
/// constants.
#[derive(Debug, Clone, Copy)]
struct PolicyCollection<'a> {
    /// Bundle-relative JSON file holding the collection.
    file_rel: &'a str,
    /// Version-relative API endpoint to POST to.
    endpoint: &'a str,
    /// Mapper resource type to register created IDs under.
    resource_type: &'a str,
    /// Which translation rules apply to this collection.
    resource: Resource,
    /// Entries carry a CEL `rule` stored as a `$celFile` pointer, which has
    /// to be read back inline before the POST.
    has_cel: bool,
    /// An HTTP 400 on one entry is a skip-with-warning rather than a hard
    /// failure.
    ///
    /// True for resources whose creation can legitimately be refused —
    /// an entry needing credentials the bundle does not hold. False for
    /// the policy classes, where a 400 means the body is wrong and
    /// continuing would hide it.
    graceful_400: bool,
}

/// The collections the pipeline replays, in dependency order.
///
/// Declared as constants rather than inline literals because the pipeline
/// function hit 190 lines of struct initialisers, at which point the order
/// — which is the actual contract — stopped being readable. Named
/// constants let [`import_bundle`] read as the list of steps it is.
mod collections {
    use super::{PolicyCollection, Resource};

    pub const SIEM: PolicyCollection<'static> = PolicyCollection {
        file_rel: "integrations/siem.json",
        endpoint: "/integrations/siem",
        resource_type: "siem-integration",
        resource: Resource::Siem,
        has_cel: false,
        graceful_400: true,
    };
    pub const EXTERNAL_GROUPS: PolicyCollection<'static> = PolicyCollection {
        file_rel: "integrations/external-groups.json",
        endpoint: "/integrations/external-group",
        resource_type: "external-group",
        resource: Resource::ExternalGroup,
        has_cel: false,
        graceful_400: true,
    };
    pub const BENCHMARK_CONTROLS: PolicyCollection<'static> = PolicyCollection {
        file_rel: "benchmark/controls.json",
        endpoint: "/benchmark/control",
        resource_type: "benchmark-control",
        resource: Resource::BenchmarkControl,
        has_cel: true,
        graceful_400: true,
    };
    pub const BENCHMARK_FRAMEWORKS: PolicyCollection<'static> = PolicyCollection {
        file_rel: "benchmark/frameworks.json",
        endpoint: "/benchmark/framework",
        resource_type: "benchmark-framework",
        resource: Resource::BenchmarkFramework,
        has_cel: false,
        graceful_400: true,
    };
    pub const ASSURANCE_CONTROLS: PolicyCollection<'static> = PolicyCollection {
        file_rel: "policies/assurance-controls.json",
        endpoint: "/policies/assurance-control",
        resource_type: "assurance-control",
        resource: Resource::AssuranceControl,
        has_cel: true,
        graceful_400: true,
    };
    pub const ADMISSION_CONTROLS: PolicyCollection<'static> = PolicyCollection {
        file_rel: "policies/admission-controls.json",
        endpoint: "/policies/admission-controller/control",
        resource_type: "admission-control",
        resource: Resource::AdmissionControl,
        has_cel: true,
        graceful_400: true,
    };
    pub const ADMISSION_POLICIES: PolicyCollection<'static> = PolicyCollection {
        file_rel: "policies/admission-controller.json",
        endpoint: "/policies/admission-controller",
        resource_type: "admission-policy",
        resource: Resource::AdmissionPolicy,
        has_cel: false,
        graceful_400: true,
    };
    pub const SCANNER_POLICIES: PolicyCollection<'static> = PolicyCollection {
        file_rel: "policies/scanner.json",
        endpoint: "/policies/scanner",
        resource_type: "scanner-policy",
        resource: Resource::ScannerPolicy,
        has_cel: false,
        // A 400 on a scanner policy means the body is wrong, not that this one
        // entry is unreplayable. Hiding it would hide a translation bug.
        graceful_400: false,
    };
    pub const ASSURANCE_POLICIES: PolicyCollection<'static> = PolicyCollection {
        file_rel: "policies/assurance.json",
        endpoint: "/policies/assurance",
        resource_type: "assurance-policy",
        resource: Resource::AssurancePolicy,
        has_cel: false,
        graceful_400: false,
    };

    /// The classes KCS 2.5 introduced, which an `APIv1` target has no route for.
    pub const V3_ONLY: &[PolicyCollection<'static>] =
        &[BENCHMARK_CONTROLS, BENCHMARK_FRAMEWORKS, ASSURANCE_CONTROLS];
    /// The 2.5 classes replayed after the policy classes they belong beside.
    pub const V3_ONLY_LATE: &[PolicyCollection<'static>] =
        &[ADMISSION_CONTROLS, ADMISSION_POLICIES];
}

/// Replays runtime profiles via `POST /policies/runtime-profile`.
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
    translator: Translator,
) -> Result<()> {
    let profiles = read_json(&bundle.join("policies/runtime-profiles.json"))?;
    let arr = match profiles.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for profile in &arr {
        let Some(src_id) = src_id_from(profile) else {
            warn_skipped_without_id("runtime profile", profile);
            continue;
        };
        let name = name_or_id(profile, "name", &src_id).to_string();
        let mut body = strip(profile);
        report_translation(
            translator,
            Resource::RuntimeProfile,
            &mut body,
            "runtime profile",
            &name,
        );
        let unscoped = remap_system_scopes(&mut body, mapper);
        warn_dropped_scopes("runtime profile", &name, &unscoped);
        let result = client.post("/policies/runtime-profile", &body).await?;
        let tgt_id = tgt_id_from(&result, &format!("runtime profile '{name}'"))?;
        mapper.register("runtime-profile", &src_id, &tgt_id);
    }
    Ok(())
}

/// Replays runtime policies via `POST /policies/runtime`. Each
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
    translator: Translator,
) -> Result<()> {
    let policies = read_json(&bundle.join("policies/runtime.json"))?;
    let arr = match policies.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for pol in &arr {
        let Some(src_id) = src_id_from(pol) else {
            warn_skipped_without_id("runtime policy", pol);
            continue;
        };
        let name = name_or_id(pol, "name", &src_id).to_string();
        let enabled = pol["enabled"].as_bool().unwrap_or(false);

        // An `APIv1` policy carries its admission controls inline; `APIv3` keeps them
        // in a separate resource. The split happens before anything is stripped or
        // rewritten, so both halves start from the full source body.
        let (runtime_src, admission_src) = translator.split_runtime_policy(pol);

        let mut body = strip(&runtime_src);
        rewrite_runtime_profile_match_blocks(&mut body, pol, &src_id, mapper)?;
        let unscoped = remap_system_scopes(&mut body, mapper);
        warn_dropped_scopes("runtime policy", &name, &unscoped);
        let result = client.post("/policies/runtime", &body).await?;
        let tgt_id = tgt_id_from(&result, &format!("runtime policy '{name}'"))?;
        mapper.register("runtime-policy", &src_id, &tgt_id);
        if enabled {
            enable_policy(client, "/policies/runtime", &tgt_id).await?;
        }

        // The admission half, when the source had admission control in use. On a
        // v1 target this is None, because no split happened.
        if let Some(admission) = admission_src {
            import_split_admission_policy(client, &admission, &name, enabled, mapper).await?;
        }
    }
    Ok(())
}

/// Creates the admission-controller policy that split off a v1 runtime
/// policy.
///
/// A failure here is reported but does not abort: the runtime half is
/// already on the target, so aborting would leave the migration half-done
/// with no way to resume. The operator is told which policy lost its
/// admission controls, which is recoverable by hand; a dead import is not.
async fn import_split_admission_policy(
    client: &KcsClient,
    admission: &Value,
    name: &str,
    enabled: bool,
    mapper: &mut IdMapper,
) -> Result<()> {
    let body = strip(admission);
    match client.post("/policies/admission-controller", &body).await {
        Ok(result) => {
            let tgt_id = tgt_id_from(&result, &format!("admission policy '{name}'"))?;
            mapper.register("admission-policy-from-runtime", name, &tgt_id);
            if enabled {
                enable_policy(client, "/policies/admission-controller", &tgt_id).await?;
            }
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "OPERATOR ACTION REQUIRED: runtime policy '{name}' was imported, but the \
                 admission-controller policy that APIv3 splits out of it was not \
                 ({e}). Its admission controls — image checks, capability blocks, \
                 registry allow-lists — are NOT active on the target. Recreate an \
                 admission policy named '{name}' in the target console."
            );
            Ok(())
        }
    }
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
        // `resolve` hands back a `&str` borrowed from `mapper`; `to_string()` ends that
        // borrow before `block` is written, which is also what lets the loop keep using
        // `mapper` on the next iteration.
        let resolved = match block.get("runtimeProfileId").and_then(Value::as_str) {
            Some(old_id) => Some(
                mapper
                    .resolve("runtime-profile", old_id)
                    .map_err(|_| {
                        anyhow!(
                            "Runtime policy '{}' references runtime profile ID '{}' \
                             that was not registered during import.",
                            name_or_id(original, "name", src_id),
                            old_id
                        )
                    })?
                    .to_string(),
            ),
            None => None,
        };
        if let Some(new_id) = resolved {
            // `as_object_mut` instead of `block["runtimeProfileId"] = …`: `IndexMut` on
            // `Value` panics when the target is not an object, so the fallible case is
            // handled here rather than left to a runtime abort.
            let obj = block.as_object_mut().ok_or_else(|| {
                anyhow!(
                    "Runtime policy '{}' has a runtimeProfileMatchBlocks entry that is \
                     not a JSON object.",
                    name_or_id(original, "name", src_id)
                )
            })?;
            obj.insert("runtimeProfileId".to_string(), Value::String(new_id));
        }
        rewritten.push(block);
    }
    let obj = body.as_object_mut().ok_or_else(|| {
        anyhow!(
            "Runtime policy '{}' body is not a JSON object.",
            name_or_id(original, "name", src_id)
        )
    })?;
    obj.insert(
        "runtimeProfileMatchBlocks".to_string(),
        Value::Array(rewritten),
    );
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
    // `.get(key)` rather than `notif_ref[key]`: indexing a `Value` yields `Null` for a
    // missing key instead of panicking, but the same habit over a `Vec` does panic, so the
    // crate denies `clippy::indexing_slicing` everywhere and uses checked access instead.
    let count = |key: &str| {
        notif_ref
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
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

/// Replays response policies via `POST /policies/response`. Each
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
    strict: bool,
) -> Result<()> {
    let policies = read_json(&bundle.join("policies/response.json"))?;
    let arr = match policies.as_array() {
        Some(a) => a.clone(),
        None => return Ok(()),
    };

    for pol in &arr {
        let Some(src_id) = src_id_from(pol) else {
            warn_skipped_without_id("response policy", pol);
            continue;
        };
        let name = name_or_id(pol, "name", &src_id).to_string();
        let enabled = pol["enabled"].as_bool().unwrap_or(false);
        let mut body = strip(pol);
        rewrite_notification_settings_ids(&mut body, pol, &src_id, mapper, strict)?;
        let unscoped = remap_system_scopes(&mut body, mapper);
        warn_dropped_scopes("response policy", &name, &unscoped);
        let result = client.post("/policies/response", &body).await?;
        let tgt_id = tgt_id_from(&result, &format!("response policy '{name}'"))?;
        mapper.register("response-policy", &src_id, &tgt_id);
        if enabled {
            enable_policy(client, "/policies/response", &tgt_id).await?;
        }
    }
    Ok(())
}

/// Rewrites the `notificationSettingsIds` array on a response-policy body
/// into the target's ID space, dropping the IDs that cannot be mapped.
///
/// `original` is used only to recover the policy name for messages.
///
/// # Why this does not abort by default
///
/// Notification channels have **no create endpoint** in either API
/// generation — `/integrations/notification-settings/{email,telegram,webhook}`
/// are GET-only — so the mapper is never populated for them. The previous
/// behaviour, aborting on any unmapped ID, therefore fired for every
/// response policy wired to a channel, which is the normal case rather
/// than an edge case: a single such policy stopped the whole import at
/// step 13, after twelve steps had already written to the target.
///
/// Dropping the IDs is not silent. Each one is reported as an
/// `OPERATOR ACTION REQUIRED` line that says the policy will evaluate and
/// notify nobody until the channel is recreated and reattached by hand — a
/// response policy that fires silently is worse than one that failed
/// loudly, so the warning has to carry that consequence.
/// `--strict-notifications` restores the abort for anyone who would rather
/// not have the target touched at all.
///
/// # Errors
///
/// With `strict` set, returns an error listing every unmapped ID.
fn rewrite_notification_settings_ids(
    body: &mut Value,
    original: &Value,
    src_id: &str,
    mapper: &IdMapper,
    strict: bool,
) -> Result<()> {
    let Some(notif_ids) = body
        .get("notificationSettingsIds")
        .and_then(|v| v.as_array())
        .cloned()
    else {
        return Ok(());
    };

    let mut resolved = Vec::with_capacity(notif_ids.len());
    let mut missing = Vec::new();
    for id_val in &notif_ids {
        if let Some(id) = id_val.as_str() {
            match mapper.resolve_opt("notification", id) {
                Some(new_id) => resolved.push(Value::String(new_id.to_string())),
                None => missing.push(id.to_string()),
            }
        }
    }

    let policy_name = name_or_id(original, "name", src_id);
    if !missing.is_empty() {
        if strict {
            return Err(anyhow!(
                "Cannot import response policy '{policy_name}': notification channel IDs \
                 are not mapped — {missing:?}. Notification channels have no create \
                 endpoint, so they must be recreated by hand on the target; drop \
                 --strict-notifications to import the policy without them."
            ));
        }
        eprintln!(
            "OPERATOR ACTION REQUIRED: response policy '{policy_name}' was imported \
             WITHOUT its notification channels {missing:?}, because channels cannot be \
             created through the API. The policy will evaluate and notify NOBODY until \
             you recreate those channels on the target and reattach them to this policy."
        );
    }

    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "notificationSettingsIds".to_string(),
            Value::Array(resolved),
        );
    }
    Ok(())
}

/// Uploads the network-reputation binary blob via
/// `PUT /policies/custom-reputation/import`. No-op if the bundle
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
        .put_bytes("/policies/custom-reputation/import", data)
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
/// use kcs_migrator::client::{KcsClient, Timeouts};
/// use kcs_migrator::importer;
/// use std::path::Path;
///
/// # async fn run() -> anyhow::Result<()> {
/// let (client, _kcs) = KcsClient::detect(
///     "https://kcs.tgt.corp", "tok", true, None, Timeouts::default(),
/// ).await?;
/// let mapper = importer::import_bundle(
///     &client, Path::new("kcs-export-…"), &importer::ImportOptions::default(),
/// ).await?;
/// # let _ = mapper;
/// # Ok(()) }
/// ```
pub async fn import_bundle(
    client: &KcsClient,
    bundle: &Path,
    options: &ImportOptions,
) -> Result<IdMapper> {
    // First, and before any request: a directory with no manifest is an
    // interrupted export, and a bundle newer than the target cannot be replayed.
    // Both are refused here so a doomed import writes nothing at all.
    let manifest = Manifest::read(bundle)?;
    let translator = Translator::new(
        manifest.api_version,
        client.api_version(),
        manifest.kcs_version,
        options.target_kcs,
    )?;

    if manifest.is_legacy() {
        eprintln!(
            "Note: this bundle is format {} (written by kcs-migrator {}), which did not \
             record an API generation; treating it as APIv1.",
            manifest.bundle_format, manifest.tool_version
        );
    }
    if !translator.is_noop() {
        eprintln!(
            "Translating bundle bodies from API{} to API{}.",
            manifest.api_version.prefix().trim_start_matches('/'),
            client.api_version().prefix().trim_start_matches('/')
        );
    }

    let mut mapper = IdMapper::new();

    import_reports_storage(client, bundle).await?;
    import_scanner_priority(client, bundle).await?;
    // Before anything that carries `systemScopes`: scopes cannot be created
    // through the API, so this reads both sides and matches them by name. It is
    // the only step that writes nothing.
    register_security_scopes(client, bundle, &mut mapper).await?;
    import_ldap(client, bundle, &mut mapper).await?;
    import_sso(client, bundle).await?;
    import_llm(client, bundle).await?;
    import_collection(client, bundle, &collections::SIEM, &mut mapper, translator).await?;
    import_image_registries(client, bundle, &mut mapper).await?;
    import_collection(
        client,
        bundle,
        &collections::EXTERNAL_GROUPS,
        &mut mapper,
        translator,
    )
    .await?;
    import_agent_groups(client, bundle, &mut mapper, translator).await?;

    // The KCS 2.5 resource classes. On an `APIv1` target they are skipped without
    // a request: 2.4 has no route for them, and a 404 would abort the import.
    let target_is_v3 = client.api_version() == ApiVersion::V3;
    import_or_skip_v3_only(
        client,
        bundle,
        collections::V3_ONLY,
        &mut mapper,
        translator,
        target_is_v3,
    )
    .await?;

    import_collection(
        client,
        bundle,
        &collections::SCANNER_POLICIES,
        &mut mapper,
        translator,
    )
    .await?;
    import_collection(
        client,
        bundle,
        &collections::ASSURANCE_POLICIES,
        &mut mapper,
        translator,
    )
    .await?;
    import_or_skip_v3_only(
        client,
        bundle,
        collections::V3_ONLY_LATE,
        &mut mapper,
        translator,
        target_is_v3,
    )
    .await?;
    import_runtime_profiles(client, bundle, &mut mapper, translator).await?;
    import_runtime_policies(client, bundle, &mut mapper, translator).await?;
    warn_notifications_reference(bundle)?;
    import_response_policies(client, bundle, &mut mapper, options.strict_notifications).await?;
    import_custom_reputation_toggle(client, bundle).await?;
    import_network_reputation(client, bundle).await?;

    Ok(mapper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Timeouts;
    use crate::version::ApiVersion;
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

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;
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

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;
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
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let err = import_bundle(&client, &bundle, &ImportOptions::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rp-ghost-99"));
        Ok(())
    }

    #[tokio::test]
    async fn import_response_policy_errors_on_unmapped_notification() -> Result<()> {
        // Strict mode is what aborts now; the default drops the channel and warns.
        let strict = ImportOptions {
            strict_notifications: true,
            ..ImportOptions::default()
        };
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
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let err = import_bundle(&client, &bundle, &strict).await.unwrap_err();
        // Complements strict_notifications_restores_the_abort: that one checks the
        // policy name and the flag name, this one checks the offending channel ID
        // reaches the operator so they know which channel to recreate.
        assert!(
            err.to_string().contains("notif-unknown-99"),
            "the unmapped channel ID must be named, got: {err}"
        );
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

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;
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

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;
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

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;
        assert_eq!(mapper.resolve("image-registry", "reg-src-1")?, "reg-tgt-1");
        Ok(())
    }

    // ---- group 6: LDAP uses POST, not a route that does not exist ----

    #[tokio::test]
    async fn ldap_is_created_with_post_and_then_enabled() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("integrations/ldap.json"),
            serde_json::to_string(&json!([
                {"id": "src-ldap", "name": "corp", "enabled": true, "bindDN": "cn=svc"}
            ]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/integrations/ldap"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "tgt-ldap"})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/integrations/ldap/tgt-ldap/enable"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;
        assert_eq!(mapper.resolve("ldap", "src-ldap")?, "tgt-ldap");

        let seen = server.received_requests().await.unwrap_or_default();
        // The regression pin: PUT /integrations/ldap returns 404 on every KCS
        // generation, which is not a graceful-skip status, so sending it aborted
        // the whole import for any source with LDAP configured.
        assert!(
            !seen.iter().any(|r| r.method == wiremock::http::Method::PUT
                && r.url.path() == "/v1/integrations/ldap"),
            "must never PUT /integrations/ldap -- that route does not exist"
        );
        assert!(seen.iter().any(|r| r.method == wiremock::http::Method::POST
            && r.url.path() == "/v1/integrations/ldap/tgt-ldap/enable"));
        Ok(())
    }

    #[tokio::test]
    async fn disabled_ldap_is_created_but_not_enabled() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("integrations/ldap.json"),
            serde_json::to_string(&json!([{"id": "s", "name": "corp", "enabled": false}]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/integrations/ldap"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "t"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        assert!(
            !seen.iter().any(|r| r.url.path().ends_with("/enable")),
            "a disabled source integration must not be switched on"
        );
        Ok(())
    }

    // ---- group 6: notifications drop instead of aborting ----

    #[tokio::test]
    async fn response_policy_imports_without_unmappable_notifications() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/response.json"),
            serde_json::to_string(&json!([{
                "id": "src-resp",
                "name": "page-on-critical",
                "enabled": false,
                "notificationSettingsIds": ["chan-a", "chan-b"],
            }]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/response"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "tgt-resp"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;
        assert_eq!(mapper.resolve("response-policy", "src-resp")?, "tgt-resp");

        // The policy was sent, with the unmappable channels removed rather than
        // passed through as stale source IDs.
        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v1/policies/response")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("the response policy should have been POSTed"))?;
        assert_eq!(body["notificationSettingsIds"], json!([]));
        Ok(())
    }

    #[tokio::test]
    async fn strict_notifications_restores_the_abort() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/response.json"),
            serde_json::to_string(&json!([{
                "id": "src-resp",
                "name": "page-on-critical",
                "notificationSettingsIds": ["chan-a"],
            }]))?,
        )?;

        let server = MockServer::start().await;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let options = ImportOptions {
            strict_notifications: true,
            ..ImportOptions::default()
        };
        let err = import_bundle(&client, &bundle, &options)
            .await
            .expect_err("strict mode must abort on an unmappable channel");
        let rendered = format!("{err}");
        assert!(rendered.contains("page-on-critical"), "names the policy");
        assert!(
            rendered.contains("--strict-notifications"),
            "tells the operator how to proceed instead, got: {rendered}"
        );
        Ok(())
    }

    // ---- group 6: security scopes remap by name ----

    /// Adds a bundle scope reference file and returns the bundle path.
    fn with_scopes(bundle: &std::path::Path, scopes: &Value) -> Result<()> {
        std::fs::create_dir_all(bundle.join("security"))?;
        std::fs::write(
            bundle.join("security/scopes-REFERENCE.json"),
            serde_json::to_string(scopes)?,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn system_scopes_are_remapped_by_name() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        with_scopes(
            &bundle,
            &json!([{"id": "src-scope", "name": "Default scope"}]),
        )?;
        std::fs::write(
            bundle.join("policies/assurance.json"),
            serde_json::to_string(&json!([{
                "id": "src-pol",
                "name": "a",
                "systemScopes": ["src-scope"],
            }]))?,
        )?;

        let server = MockServer::start().await;
        // The same scope exists on the target under a different ID -- which is the
        // whole problem, since scopes cannot be created through the API.
        Mock::given(method("GET"))
            .and(path("/v1/security/scopes"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([{"id": "tgt-scope", "name": "Default scope"}])),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/assurance"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "t"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v1/policies/assurance")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("assurance policy should have been POSTed"))?;
        assert_eq!(
            body["systemScopes"],
            json!(["tgt-scope"]),
            "the source scope ID must be rewritten, not passed through -- the target \
             accepts a stale ID and scopes the policy to nothing"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unmatched_scope_names_are_dropped_not_passed_through() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        with_scopes(&bundle, &json!([{"id": "src-scope", "name": "lab-only"}]))?;
        std::fs::write(
            bundle.join("policies/assurance.json"),
            serde_json::to_string(&json!([{
                "id": "p", "name": "a", "systemScopes": ["src-scope"],
            }]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/security/scopes"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([{"id": "tgt", "name": "Default scope"}])),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/assurance"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "t"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v1/policies/assurance")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("assurance policy should have been POSTed"))?;
        assert_eq!(body["systemScopes"], json!([]));
        Ok(())
    }

    #[tokio::test]
    async fn a_bundle_without_a_scope_file_leaves_system_scopes_alone() -> Result<()> {
        // Backward compatibility: a 0.1.0 bundle records no scopes, and emptying
        // every scope array would be worse than leaving them as they were.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/assurance.json"),
            serde_json::to_string(&json!([{
                "id": "p", "name": "a", "systemScopes": ["src-scope"],
            }]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/assurance"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "t"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        assert!(
            !seen.iter().any(|r| r.url.path() == "/v1/security/scopes"),
            "with no scope file there is nothing to match against, so do not ask"
        );
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v1/policies/assurance")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("assurance policy should have been POSTed"))?;
        assert_eq!(body["systemScopes"], json!(["src-scope"]));
        Ok(())
    }

    // ---- group 6: a created resource with no id is fatal ----

    #[tokio::test]
    async fn a_create_that_returns_no_id_aborts_and_names_the_resource() -> Result<()> {
        // This used to register "" as the target ID. Every later FK rewrite then
        // resolved to "", the POST was accepted, and the operator was left with
        // policies pointing at nothing -- with no error anywhere.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/runtime-profiles.json"),
            serde_json::to_string(&json!([{"id": "src-prof", "name": "busybox-profile"}]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/runtime-profile"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"ok": true})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let err = import_bundle(&client, &bundle, &ImportOptions::default())
            .await
            .expect_err("a create with no id must abort");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("busybox-profile"),
            "names the resource, got: {rendered}"
        );
        assert!(rendered.contains("no id"), "says what went wrong");
        Ok(())
    }

    #[tokio::test]
    async fn a_bundle_entry_without_an_id_is_skipped_not_registered_under_an_empty_key(
    ) -> Result<()> {
        // Two id-less entries would both have registered under "", so the second
        // silently overwrote the first's mapping.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/runtime-profiles.json"),
            serde_json::to_string(&json!([
                {"name": "no-id-one"},
                {"id": "has-id", "name": "keeper"},
            ]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/runtime-profile"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "tgt"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        assert_eq!(mapper.resolve("runtime-profile", "has-id")?, "tgt");
        assert_eq!(mapper.resolve_opt("runtime-profile", ""), None);
        let posts = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == "/v1/policies/runtime-profile")
            .count();
        assert_eq!(posts, 1, "the id-less entry is skipped, not sent");
        Ok(())
    }

    // ---- group 7: the manifest gates the import ----

    /// Overwrites a bundle's manifest with `raw`.
    fn set_manifest(bundle: &std::path::Path, raw: &Value) -> Result<()> {
        std::fs::write(bundle.join("manifest.json"), serde_json::to_string(raw)?)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_bundle_with_no_manifest_is_refused_before_any_request() -> Result<()> {
        // The manifest is written last, so its absence means the export was
        // interrupted. Replaying a partial bundle would write a partial
        // configuration and report success.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::remove_file(bundle.join("manifest.json"))?;

        let server = MockServer::start().await;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let err = import_bundle(&client, &bundle, &ImportOptions::default())
            .await
            .expect_err("a manifest-less directory must be refused");
        assert!(format!("{err}").contains("not a complete bundle"));
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "nothing may be sent to the target before the bundle is accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_v3_bundle_into_a_v1_target_is_refused_before_any_request() -> Result<()> {
        // The downgrade check lives in Translator::new, which import_bundle calls
        // before step 1. This is the test that proves "aborts with zero side
        // effects" rather than asserting it in a doc comment.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        set_manifest(
            &bundle,
            &json!({
                "tool_version": "0.2.0",
                "bundle_format": 2,
                "api_version": "v3",
                "kcs_version": "2.5.0",
            }),
        )?;

        let server = MockServer::start().await;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        let options = ImportOptions {
            target_kcs: Some(KcsVersion::new(2, 4, 1)),
            ..ImportOptions::default()
        };
        let err = import_bundle(&client, &bundle, &options)
            .await
            .expect_err("a downgrade must be refused");

        let rendered = format!("{err}");
        assert!(rendered.contains("KCS 2.5.0"), "names the bundle release");
        assert!(rendered.contains("KCS 2.4.1"), "names the target release");
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a refused downgrade must leave the target completely untouched, got {} \
             request(s)",
            server.received_requests().await.unwrap_or_default().len()
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_format_1_bundle_still_imports_as_v1() -> Result<()> {
        // Exactly what 0.1.0 wrote: no bundle_format, no api_version.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        set_manifest(
            &bundle,
            &json!({"tool_version": "0.1.0", "timestamp": "2026-05-21_16-58-53"}),
        )?;

        let server = MockServer::start().await;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;
        Ok(())
    }

    // ---- group 7: a v1 bundle is actually translated on the way to a v3 target ----

    #[tokio::test]
    async fn a_v1_assurance_policy_is_translated_before_it_is_posted() -> Result<()> {
        // The end-to-end claim: translate.rs is wired in, not merely present.
        // Without this the bundle's failCICDStep reaches a v3 endpoint that wants
        // failExternalScansStep, and the field is ignored -- silently losing the
        // setting with a 201 in reply.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        set_manifest(
            &bundle,
            &json!({
                "tool_version": "0.2.0",
                "bundle_format": 2,
                "api_version": "v1",
                "kcs_version": "2.4.1",
            }),
        )?;
        std::fs::write(
            bundle.join("policies/assurance.json"),
            serde_json::to_string(&json!([{
                "id": "src-pol",
                "name": "block-criticals",
                "failCICDStep": true,
                "customControls": [{"id": "c1"}],
            }]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/policies/assurance"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "t"})))
            .mount(&server)
            .await;

        // A V3 client against a V1 bundle: the only combination that translates.
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V3,
            Timeouts::default(),
        )?;
        let options = ImportOptions {
            target_kcs: Some(KcsVersion::new(2, 5, 0)),
            ..ImportOptions::default()
        };
        import_bundle(&client, &bundle, &options).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v3/policies/assurance")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("the assurance policy should have been POSTed"))?;

        assert_eq!(body["failExternalScansStep"], json!(true), "renamed");
        assert!(
            body.get("failCICDStep").is_none(),
            "old spelling must be gone"
        );
        assert!(
            body.get("customControls").is_none(),
            "inline custom controls became their own resource in 2.5"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_v1_runtime_profile_has_its_audit_typos_fixed_before_posting() -> Result<()> {
        // The nested rename, end to end. It depends on fileOperationsRules being
        // in the bundle at all, which is why group 6 switched this class to the
        // per-item detail fetch -- the list projection omits it.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        set_manifest(
            &bundle,
            &json!({"bundle_format": 2, "api_version": "v1", "kcs_version": "2.4.1"}),
        )?;
        std::fs::write(
            bundle.join("policies/runtime-profiles.json"),
            serde_json::to_string(&json!([{
                "id": "src-prof",
                "name": "busybox",
                "fileOperationsRules": {"items": [{
                    "paths": ["/etc"],
                    "auditEvents": {"auditWritEvents": true, "auditRenameOrEvents": true},
                }]},
            }]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/policies/runtime-profile"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "t"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V3,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v3/policies/runtime-profile")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("the runtime profile should have been POSTed"))?;

        let events = &body["fileOperationsRules"]["items"][0]["auditEvents"];
        assert_eq!(events["auditWriteEvents"], json!(true));
        assert_eq!(events["auditRenameOrMoveEvents"], json!(true));
        assert!(events.get("auditWritEvents").is_none());
        assert!(events.get("auditRenameOrEvents").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn a_v3_bundle_into_a_v3_target_is_sent_unchanged() -> Result<()> {
        // Same-generation import must be the identity. A v3 bundle already uses
        // the new spellings, so translating again would corrupt it.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        set_manifest(
            &bundle,
            &json!({"bundle_format": 2, "api_version": "v3", "kcs_version": "2.5.0"}),
        )?;
        std::fs::write(
            bundle.join("policies/assurance.json"),
            serde_json::to_string(&json!([{
                "id": "p", "name": "a", "failExternalScansStep": true,
            }]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/policies/assurance"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "t"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V3,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v3/policies/assurance")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("the assurance policy should have been POSTed"))?;
        assert_eq!(body["failExternalScansStep"], json!(true));
        Ok(())
    }

    #[tokio::test]
    async fn a_v1_agent_group_is_translated_before_it_is_posted() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        set_manifest(
            &bundle,
            &json!({"bundle_format": 2, "api_version": "v1", "kcs_version": "2.4.1"}),
        )?;
        std::fs::write(
            bundle.join("integrations/agent-groups.json"),
            serde_json::to_string(&json!([{
                "id": "src-g",
                "groupName": "k8s",
                "fileThreatProtectionProxyUrl": "http://proxy.example.invalid:3128",
                "networkReputationSource": "kcs-list",
                "fileThreatProtectionMalwareDbUrl": "https://db.example.invalid",
            }]))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/integrations/agent-group"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "tgt-g"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V3,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v3/integrations/agent-group")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("the agent group should have been POSTed"))?;

        assert_eq!(
            body["networkSettingsProxyUrl"],
            json!("http://proxy.example.invalid:3128")
        );
        assert_eq!(body["networkSettingsSource"], json!("kcs-list"));
        assert!(body.get("fileThreatProtectionProxyUrl").is_none());
        assert!(body.get("networkReputationSource").is_none());
        assert!(body.get("fileThreatProtectionMalwareDbUrl").is_none());
        Ok(())
    }

    // ---- group 8: the six new resources ----

    /// Mounts a POST that returns a fresh id, for each path given.
    async fn mount_creates(server: &MockServer, paths: &[(&str, &str)]) {
        for (p, id) in paths {
            Mock::given(method("POST"))
                .and(path(*p))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": *id})))
                .mount(server)
                .await;
        }
    }

    /// A format-2 v3 bundle, so the new resource classes are in scope.
    fn make_v3_bundle(tmp: &tempfile::TempDir) -> Result<std::path::PathBuf> {
        let bundle = make_bundle(tmp)?;
        set_manifest(
            &bundle,
            &json!({
                "tool_version": "0.2.0",
                "bundle_format": 2,
                "api_version": "v3",
                "kcs_version": "2.5.0",
            }),
        )?;
        Ok(bundle)
    }

    fn v3_client(uri: &str) -> Result<KcsClient> {
        KcsClient::new(uri, "tok", true, None, ApiVersion::V3, Timeouts::default())
    }

    #[tokio::test]
    async fn siem_integrations_are_imported() -> Result<()> {
        // The README claimed SIEM was Helm-values-only. It has a full CRUD API in
        // both generations, and its POST body carries no credentials, so unlike
        // image registries it replays cleanly.
        let tmp = tempfile::tempdir()?;
        let bundle = make_v3_bundle(&tmp)?;
        std::fs::write(
            bundle.join("integrations/siem.json"),
            serde_json::to_string(&json!([{
                "id": "src-siem",
                "name": "corp-splunk",
                "address": "siem.example.invalid",
                "port": 514,
                "protocol": "tcp",
                "exportedData": ["vulnerabilities", "runtime"],
            }]))?,
        )?;

        let server = MockServer::start().await;
        mount_creates(&server, &[("/v3/integrations/siem", "tgt-siem")]).await;
        let client = v3_client(&server.uri())?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        assert_eq!(mapper.resolve("siem-integration", "src-siem")?, "tgt-siem");
        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v3/integrations/siem")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("SIEM should have been POSTed"))?;
        assert_eq!(body["address"], json!("siem.example.invalid"));
        assert_eq!(body["port"], json!(514));
        assert_eq!(body["exportedData"][1], json!("runtime"));
        Ok(())
    }

    #[tokio::test]
    async fn external_groups_are_imported() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_v3_bundle(&tmp)?;
        std::fs::write(
            bundle.join("integrations/external-groups.json"),
            serde_json::to_string(&json!([{
                "id": "src-eg", "groupName": "ci-runners", "description": "CI",
            }]))?,
        )?;

        let server = MockServer::start().await;
        mount_creates(&server, &[("/v3/integrations/external-group", "tgt-eg")]).await;
        let client = v3_client(&server.uri())?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;
        assert_eq!(mapper.resolve("external-group", "src-eg")?, "tgt-eg");
        Ok(())
    }

    #[tokio::test]
    async fn a_cel_rule_is_inlined_from_its_file_before_the_post() -> Result<()> {
        // The CEL round-trip that matters: export wrote the rule to a .cel file
        // and left a pointer, so import has to read the file back. If it POSTed
        // the pointer object instead, the server would reject it or store a
        // control with no rule.
        const RULE: &str = "object.spec.containers.all(c,\n  c.image != \"latest\"\n)";

        let tmp = tempfile::tempdir()?;
        let bundle = make_v3_bundle(&tmp)?;
        std::fs::create_dir_all(bundle.join("CEL/benchmark/control"))?;
        std::fs::write(bundle.join("CEL/benchmark/control/CTRL-9001.cel"), RULE)?;
        std::fs::create_dir_all(bundle.join("benchmark"))?;
        std::fs::write(
            bundle.join("benchmark/controls.json"),
            serde_json::to_string(&json!([{
                "id": "src-ctl",
                "controlId": "CTRL-9001",
                "name": "no latest tag",
                "rule": {"$celFile": "CEL/benchmark/control/CTRL-9001.cel"},
            }]))?,
        )?;

        let server = MockServer::start().await;
        mount_creates(&server, &[("/v3/benchmark/control", "tgt-ctl")]).await;
        let client = v3_client(&server.uri())?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v3/benchmark/control")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("the benchmark control should have been POSTed"))?;
        assert_eq!(
            body["rule"],
            json!(RULE),
            "the rule must arrive as the inline string the API expects"
        );
        assert!(
            body["rule"].get("$celFile").is_none(),
            "the pointer must never reach the server"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_cel_pointer_that_escapes_the_bundle_aborts_the_import() -> Result<()> {
        // A bundle is hand-editable, so this is reachable input.
        let tmp = tempfile::tempdir()?;
        let bundle = make_v3_bundle(&tmp)?;
        std::fs::create_dir_all(bundle.join("benchmark"))?;
        std::fs::write(
            bundle.join("benchmark/controls.json"),
            serde_json::to_string(&json!([{
                "id": "c", "controlId": "X", "rule": {"$celFile": "../../../etc/passwd"},
            }]))?,
        )?;

        let server = MockServer::start().await;
        let client = v3_client(&server.uri())?;
        let err = import_bundle(&client, &bundle, &ImportOptions::default())
            .await
            .expect_err("a traversing CEL pointer must abort");
        assert!(format!("{err}").contains("escapes the bundle"));
        Ok(())
    }

    #[tokio::test]
    async fn admission_controller_policies_are_imported_and_enabled() -> Result<()> {
        // The resource the migrator was completely blind to. A 2.5-to-2.5
        // migration used to drop all admission control silently.
        let tmp = tempfile::tempdir()?;
        let bundle = make_v3_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/admission-controller.json"),
            serde_json::to_string(&json!([{
                "id": "src-adm",
                "name": "block-privileged",
                "enabled": true,
                "enforcementMode": "enforce",
                "useCapabilityBlock": true,
                "capabilityBlock": ["CAP_SYS_ADMIN"],
            }]))?,
        )?;

        let server = MockServer::start().await;
        mount_creates(&server, &[("/v3/policies/admission-controller", "tgt-adm")]).await;
        Mock::given(method("POST"))
            .and(path("/v3/policies/admission-controller/tgt-adm/enable"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let client = v3_client(&server.uri())?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;
        assert_eq!(mapper.resolve("admission-policy", "src-adm")?, "tgt-adm");

        let seen = server.received_requests().await.unwrap_or_default();
        assert!(
            seen.iter()
                .any(|r| r.url.path() == "/v3/policies/admission-controller/tgt-adm/enable"),
            "an enabled source policy must be enabled on the target"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_custom_reputation_list_selection_is_restored() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_v3_bundle(&tmp)?;
        std::fs::write(
            bundle.join("policies/custom-reputation.json"),
            serde_json::to_string(&json!({"enabledList": "kcs-list", "total": 0}))?,
        )?;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/policies/custom-reputation/toggle"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let client = v3_client(&server.uri())?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let body: Value = seen
            .iter()
            .find(|r| r.url.path() == "/v3/policies/custom-reputation/toggle")
            .map(|r| serde_json::from_slice(&r.body))
            .transpose()?
            .ok_or_else(|| anyhow!("the toggle should have been POSTed"))?;
        assert_eq!(body["enabledList"], json!("kcs-list"));
        Ok(())
    }

    // ---- group 8: the runtime policy split, end to end ----

    #[tokio::test]
    async fn a_v1_runtime_policy_becomes_two_v3_resources() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        set_manifest(
            &bundle,
            &json!({"bundle_format": 2, "api_version": "v1", "kcs_version": "2.4.1"}),
        )?;
        std::fs::write(
            bundle.join("policies/runtime.json"),
            serde_json::to_string(&json!([{
                "id": "src-rt",
                "name": "forensics",
                "type": "container",
                "enabled": true,
                "enforcementMode": "audit",
                "useCapabilityBlock": true,
                "capabilityBlock": ["CAP_SYS_ADMIN"],
                "useContainerRuntimeProfiles": true,
                "runtimeProfileMatchBlocks": [],
            }]))?,
        )?;

        let server = MockServer::start().await;
        mount_creates(
            &server,
            &[
                ("/v3/policies/runtime", "tgt-rt"),
                ("/v3/policies/admission-controller", "tgt-adm"),
            ],
        )
        .await;
        for p in [
            "/v3/policies/runtime/tgt-rt/enable",
            "/v3/policies/admission-controller/tgt-adm/enable",
        ] {
            Mock::given(method("POST"))
                .and(path(p))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
                .mount(&server)
                .await;
        }

        let client = v3_client(&server.uri())?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let body_at = |p: &str| -> Option<Value> {
            seen.iter()
                .find(|r| r.url.path() == p)
                .and_then(|r| serde_json::from_slice(&r.body).ok())
        };

        let runtime = body_at("/v3/policies/runtime")
            .ok_or_else(|| anyhow!("runtime half should have been POSTed"))?;
        let admission = body_at("/v3/policies/admission-controller")
            .ok_or_else(|| anyhow!("admission half should have been POSTed"))?;

        // The admission fields left the runtime half entirely.
        assert!(runtime.get("useCapabilityBlock").is_none());
        assert!(runtime.get("capabilityBlock").is_none());
        assert_eq!(runtime["useContainerRuntimeProfiles"], json!(true));

        // And arrived on the admission half, with the name that pairs them.
        assert_eq!(admission["useCapabilityBlock"], json!(true));
        assert_eq!(admission["capabilityBlock"][0], json!("CAP_SYS_ADMIN"));
        assert_eq!(admission["name"], json!("forensics"));
        assert_eq!(admission["enforcementMode"], json!("audit"));
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_admission_half_warns_but_keeps_the_import_alive() -> Result<()> {
        // The runtime half is already on the target by then, so aborting would
        // leave a half-done migration with no way to resume. A named warning is
        // recoverable by hand; a dead import is not.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        set_manifest(
            &bundle,
            &json!({"bundle_format": 2, "api_version": "v1", "kcs_version": "2.4.1"}),
        )?;
        std::fs::write(
            bundle.join("policies/runtime.json"),
            serde_json::to_string(&json!([{
                "id": "r", "name": "forensics", "useCapabilityBlock": true,
                "capabilityBlock": ["CAP_SYS_ADMIN"],
            }]))?,
        )?;

        let server = MockServer::start().await;
        mount_creates(&server, &[("/v3/policies/runtime", "tgt-rt")]).await;
        Mock::given(method("POST"))
            .and(path("/v3/policies/admission-controller"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = v3_client(&server.uri())?;
        let mapper = import_bundle(&client, &bundle, &ImportOptions::default()).await?;
        // The import completed, and the runtime half is recorded.
        assert_eq!(mapper.resolve("runtime-policy", "r")?, "tgt-rt");

        // And the admission half was genuinely attempted. Without this the test
        // also passes when the split is never wired at all, which is the state
        // this group is meant to have left behind.
        let seen = server.received_requests().await.unwrap_or_default();
        assert!(
            seen.iter()
                .any(|r| r.url.path() == "/v3/policies/admission-controller"),
            "the admission half must be attempted before it can fail gracefully"
        );
        // No mapping for it, since it never got an id.
        assert_eq!(
            mapper.resolve_opt("admission-policy-from-runtime", "forensics"),
            None
        );
        Ok(())
    }

    // ---- group 8: v3-only resources are skipped on a v1 target ----

    #[tokio::test]
    async fn v3_only_resources_are_skipped_on_a_v1_target_without_a_request() -> Result<()> {
        // KCS 2.4 has no route for these, and 404 is not a graceful-skip status,
        // so attempting them would abort the whole import.
        let tmp = tempfile::tempdir()?;
        let bundle = make_bundle(&tmp)?;
        std::fs::create_dir_all(bundle.join("benchmark"))?;
        std::fs::write(
            bundle.join("benchmark/controls.json"),
            serde_json::to_string(&json!([{"id": "c", "controlId": "X", "rule": "true"}]))?,
        )?;
        std::fs::write(
            bundle.join("policies/admission-controller.json"),
            serde_json::to_string(&json!([{"id": "a", "name": "adm"}]))?,
        )?;

        let server = MockServer::start().await;
        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        for forbidden in [
            "/v1/benchmark/control",
            "/v1/benchmark/framework",
            "/v1/policies/assurance-control",
            "/v1/policies/admission-controller",
            "/v1/policies/admission-controller/control",
        ] {
            assert!(
                !seen.iter().any(|r| r.url.path() == forbidden),
                "{forbidden} must not be attempted against an APIv1 target"
            );
        }
        Ok(())
    }

    // ---- group 8: dependency order is the contract ----

    #[tokio::test]
    async fn the_pipeline_creates_resources_in_dependency_order() -> Result<()> {
        // The order IS the contract: a framework names its controls, an assurance
        // policy its custom controls, a runtime policy its profiles. Nothing else
        // in the suite would catch a reordering.
        let tmp = tempfile::tempdir()?;
        let bundle = make_v3_bundle(&tmp)?;
        std::fs::create_dir_all(bundle.join("benchmark"))?;

        let one = |v: Value| serde_json::to_string(&json!([v]));
        std::fs::write(
            bundle.join("integrations/siem.json"),
            one(json!({"id": "s", "name": "siem"}))?,
        )?;
        std::fs::write(
            bundle.join("integrations/external-groups.json"),
            one(json!({"id": "e", "groupName": "eg"}))?,
        )?;
        std::fs::write(
            bundle.join("benchmark/controls.json"),
            one(json!({"id": "bc", "controlId": "C1"}))?,
        )?;
        std::fs::write(
            bundle.join("benchmark/frameworks.json"),
            one(json!({"id": "bf", "name": "fw"}))?,
        )?;
        std::fs::write(
            bundle.join("policies/assurance-controls.json"),
            one(json!({"id": "ac", "name": "ac"}))?,
        )?;
        std::fs::write(
            bundle.join("policies/admission-controls.json"),
            one(json!({"id": "adc", "name": "adc"}))?,
        )?;
        std::fs::write(
            bundle.join("policies/admission-controller.json"),
            one(json!({"id": "adp", "name": "adp"}))?,
        )?;
        std::fs::write(
            bundle.join("policies/runtime-profiles.json"),
            one(json!({"id": "rp", "name": "rp"}))?,
        )?;

        let server = MockServer::start().await;
        mount_creates(
            &server,
            &[
                ("/v3/integrations/siem", "t-s"),
                ("/v3/integrations/external-group", "t-e"),
                ("/v3/benchmark/control", "t-bc"),
                ("/v3/benchmark/framework", "t-bf"),
                ("/v3/policies/assurance-control", "t-ac"),
                ("/v3/policies/admission-controller/control", "t-adc"),
                ("/v3/policies/admission-controller", "t-adp"),
                ("/v3/policies/runtime-profile", "t-rp"),
            ],
        )
        .await;

        let client = v3_client(&server.uri())?;
        import_bundle(&client, &bundle, &ImportOptions::default()).await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let order: Vec<String> = seen
            .iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .map(|r| r.url.path().to_string())
            .collect();

        let at = |p: &str| -> Result<usize> {
            order
                .iter()
                .position(|seen| seen == p)
                .ok_or_else(|| anyhow!("{p} was never POSTed; order was {order:?}"))
        };

        // Controls before their consumers.
        assert!(at("/v3/benchmark/control")? < at("/v3/benchmark/framework")?);
        assert!(
            at("/v3/policies/admission-controller/control")?
                < at("/v3/policies/admission-controller")?
        );
        // Integrations before the policies that may reference them.
        assert!(at("/v3/integrations/siem")? < at("/v3/policies/runtime-profile")?);
        assert!(at("/v3/integrations/external-group")? < at("/v3/policies/runtime-profile")?);
        // Assurance controls before assurance policies would run.
        assert!(at("/v3/policies/assurance-control")? < at("/v3/policies/admission-controller")?);
        Ok(())
    }
}
