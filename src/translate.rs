//! # Overview
//!
//! Rewrites bundle bodies from the API generation that produced them into
//! the one the target instance speaks.
//!
//! Translation is **forward-only**: `APIv1` → `APIv3`. A v3 bundle aimed at a
//! v1 target is refused by [`Translator::new`], before a single request
//! is sent, because 2.5-only fields have nowhere to go in 2.4 and
//! silently dropping them would hand the operator a target that looks
//! migrated and is not.
//!
//! # Where the rules come from
//!
//! Every rule below was established by diffing live per-item `GET`
//! responses for the *same object id* through `/api/v1/` and `/api/v3/`
//! on a KCS 2.5.0 instance. The published v3 `OpenAPI` document was not
//! used as the source of truth: it is demonstrably stale — it omits
//! `pullMode` and `repositoryPathMode` from the image-registry schema
//! while the server returns both, and the v1 and v3 registry payloads are
//! byte-identical. Generating this table from that document would have
//! encoded the staleness as a translation rule and corrupted registries
//! that need no translation at all.
//!
//! # The two shapes of change
//!
//! Most drift is field-level — a rename or a removal — and is handled by
//! [`Translator::resource`]. One change is structural: in `APIv3` the
//! admission controls left runtime policies and became their own
//! resource, so one v1 runtime policy becomes two v3 resources. That is
//! [`Translator::split_runtime_policy`].

use serde_json::{Map, Value};
use thiserror::Error;

use crate::version::{ApiVersion, KcsVersion};

/// Fields that moved out of a runtime policy and into an
/// admission-controller policy in `APIv3`.
///
/// Verified against the live 2.5.0 instance: a v1 runtime policy carries
/// all sixteen, the v3 runtime policy for the same id carries none of
/// them, and the v3 admission-controller policy carries exactly these.
const ADMISSION_FIELDS: &[&str] = &[
    "useBypassCriteria",
    "bypassCriteria",
    "useBestPracticeCheck",
    "bestPracticeCheck",
    "useBlockNonCompliantImages",
    "useBlockUnregisteredImages",
    "useCapabilityBlock",
    "capabilityBlock",
    "useLimitContainerPrivileges",
    "limitContainerPrivileges",
    "useRegistriesAllowed",
    "registriesAllowed",
    "useVolumesBlocked",
    "volumesBlocked",
    "useImageContentTrust",
    "signCheckPolicies",
];

/// Fields copied — not moved — from the runtime policy onto the
/// admission-controller policy that splits off it.
///
/// `name` is load-bearing rather than cosmetic: on the live 2.5 instance
/// the runtime policy and its admission-controller counterpart are
/// distinct resources with distinct ids that share a name, so copying the
/// name is what preserves the pairing an operator sees in the console.
const ADMISSION_SHARED_FIELDS: &[&str] = &[
    "name",
    "description",
    "enabled",
    "enforcementMode",
    "systemScopes",
];

/// # Overview
///
/// A bundle resource kind, as the importer replays it.
///
/// Every kind the bundle carries is listed, including the many that need
/// no translation. [`Translator::resource`] matches on this
/// exhaustively, so adding a resource to the bundle will not compile
/// until someone has stated what happens to it across generations. A
/// catch-all arm would turn that forced decision into a silent default of
/// "change nothing", which is the wrong default for a vendor API that has
/// already drifted once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    /// `/integrations/image-registries`
    ImageRegistry,
    /// `/integrations/agent-group`
    AgentGroup,
    /// `/integrations/ldap`
    Ldap,
    /// `/integrations/sso`
    Sso,
    /// `/integrations/llm`
    Llm,
    /// `/integrations/siem`
    Siem,
    /// `/integrations/external-group`
    ExternalGroup,
    /// `/policies/scanner`
    ScannerPolicy,
    /// `/policies/assurance`
    AssurancePolicy,
    /// `/policies/assurance-control`
    AssuranceControl,
    /// `/policies/admission-controller`
    AdmissionPolicy,
    /// `/policies/admission-controller/control`
    AdmissionControl,
    /// `/policies/runtime-profile`
    RuntimeProfile,
    /// `/policies/runtime`
    RuntimePolicy,
    /// `/policies/response`
    ResponsePolicy,
    /// `/benchmark/framework`
    BenchmarkFramework,
    /// `/benchmark/control`
    BenchmarkControl,
    /// `/scanners/priority`
    ScannerPriority,
    /// `/reports/storage/config`
    ReportsStorage,
}

/// # Overview
///
/// What a translation actually did to one body.
///
/// Returned rather than logged so the library does not decide how to talk
/// to the operator, and so tests can assert on the exact set of changes
/// instead of scraping stderr.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Changes {
    /// `(old_name, new_name)` for each field renamed.
    pub renamed: Vec<(String, String)>,
    /// Fields removed because `APIv3` has nowhere to put them.
    pub dropped: Vec<String>,
}

impl Changes {
    /// Whether the body was left untouched.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.renamed.is_empty() && self.dropped.is_empty()
    }
}

/// # Overview
///
/// Refusals from [`Translator::new`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TranslateError {
    /// A newer bundle was aimed at an older target.
    #[error(
        "cannot import an APIv3 bundle (from {bundle_kcs}) into an APIv1 target \
         ({target_kcs}): downgrade is not supported, because KCS 2.5 resources such as \
         admission-controller policies and custom benchmark frameworks have no \
         equivalent in 2.4. Export from the older instance instead."
    )]
    Downgrade {
        /// The bundle's source release, or `"unknown"`.
        bundle_kcs: String,
        /// The target's release, or `"unknown"`.
        target_kcs: String,
    },
}

/// Renders an optional release for an error message.
fn describe(version: Option<KcsVersion>) -> String {
    version.map_or_else(|| "unknown version".to_string(), |v| format!("KCS {v}"))
}

/// # Overview
///
/// Rewrites bodies from the `from` generation into the `to` generation.
///
/// Construct it once per import and reuse it: it holds no per-resource
/// state, so the same translator serves every step of the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translator {
    from: ApiVersion,
    to: ApiVersion,
}

impl Translator {
    /// # Overview
    ///
    /// Builds a translator from a bundle's generation to a target's.
    ///
    /// The downgrade check lives here, in the constructor, rather than in
    /// [`Self::resource`]. That placement is the whole guarantee: an
    /// import that cannot work fails while the importer is still deciding
    /// what to do, so nothing has been written to the target and there is
    /// no half-migrated instance to clean up.
    ///
    /// The two release arguments are for the error message only; the
    /// decision is made on the generations.
    ///
    /// # Errors
    ///
    /// [`TranslateError::Downgrade`] when `from` is `APIv3` and `to` is
    /// `APIv1`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kcs_migrator::translate::Translator;
    /// use kcs_migrator::version::{ApiVersion, KcsVersion};
    ///
    /// // A 2.4 bundle into a 2.5 target: the direction that translates.
    /// let t = Translator::new(ApiVersion::V1, ApiVersion::V3, None, None)?;
    /// assert!(!t.is_noop());
    ///
    /// // Same generation: the identity.
    /// let same = Translator::new(ApiVersion::V3, ApiVersion::V3, None, None)?;
    /// assert!(same.is_noop());
    ///
    /// // Downgrade is refused here, before any request is sent.
    /// assert!(Translator::new(
    ///     ApiVersion::V3,
    ///     ApiVersion::V1,
    ///     Some(KcsVersion::new(2, 5, 0)),
    ///     Some(KcsVersion::new(2, 4, 1)),
    /// )
    /// .is_err());
    /// # Ok::<(), kcs_migrator::translate::TranslateError>(())
    /// ```
    pub fn new(
        from: ApiVersion,
        to: ApiVersion,
        bundle_kcs: Option<KcsVersion>,
        target_kcs: Option<KcsVersion>,
    ) -> Result<Self, TranslateError> {
        if from == ApiVersion::V3 && to == ApiVersion::V1 {
            return Err(TranslateError::Downgrade {
                bundle_kcs: describe(bundle_kcs),
                target_kcs: describe(target_kcs),
            });
        }
        Ok(Self { from, to })
    }

    /// # Overview
    ///
    /// Whether this translator changes anything at all.
    ///
    /// True only for `APIv1` → `APIv3`; a same-generation import is the
    /// identity.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.from == self.to
    }

    /// # Overview
    ///
    /// Applies the field-level rules for `resource` to `body`, in place.
    ///
    /// A no-op when the bundle and target speak the same generation, and
    /// a no-op for every resource whose shape did not drift. Structural
    /// change — the runtime policy split — is
    /// [`Self::split_runtime_policy`], not this.
    ///
    /// # Examples
    ///
    /// ```
    /// use kcs_migrator::translate::{Resource, Translator};
    /// use kcs_migrator::version::ApiVersion;
    /// use serde_json::json;
    ///
    /// let t = Translator::new(ApiVersion::V1, ApiVersion::V3, None, None)?;
    /// let mut policy = json!({"name": "p", "failCICDStep": true});
    ///
    /// let changes = t.resource(Resource::AssurancePolicy, &mut policy);
    ///
    /// assert_eq!(policy["failExternalScansStep"], json!(true));
    /// assert!(policy.get("failCICDStep").is_none());
    /// assert_eq!(changes.renamed.len(), 1);
    /// # Ok::<(), kcs_migrator::translate::TranslateError>(())
    /// ```
    pub fn resource(&self, resource: Resource, body: &mut Value) -> Changes {
        if self.is_noop() {
            return Changes::default();
        }
        // Only v1 -> v3 remains: `new` refuses v3 -> v1, and v1 -> v1 and
        // v3 -> v3 are both caught by `is_noop` above.
        match resource {
            Resource::AgentGroup => Self::translate_agent_group(body),
            Resource::AssurancePolicy => Self::translate_assurance_policy(body),
            Resource::RuntimeProfile => Self::translate_runtime_profile(body),

            // Verified unchanged between generations on live payloads. Listed
            // individually rather than behind a `_` arm so a new resource cannot
            // inherit "no translation" without someone saying so.
            Resource::ImageRegistry
            | Resource::Ldap
            | Resource::Sso
            | Resource::Llm
            | Resource::Siem
            | Resource::ExternalGroup
            | Resource::ScannerPolicy
            | Resource::AssuranceControl
            | Resource::AdmissionPolicy
            | Resource::AdmissionControl
            | Resource::RuntimePolicy
            | Resource::ResponsePolicy
            | Resource::BenchmarkFramework
            | Resource::BenchmarkControl
            | Resource::ScannerPriority
            | Resource::ReportsStorage => Changes::default(),
        }
    }

    /// Renames `from` to `to` inside `obj`, if present.
    ///
    /// Uses `remove` then `insert` rather than reading and overwriting so
    /// the old key cannot survive alongside the new one — a body carrying
    /// both spellings is rejected by the v3 endpoints.
    fn rename(obj: &mut Map<String, Value>, from: &str, to: &str, changes: &mut Changes) {
        if let Some(value) = obj.remove(from) {
            obj.insert(to.to_string(), value);
            changes.renamed.push((from.to_string(), to.to_string()));
        }
    }

    /// Removes `field` from `obj`, if present.
    fn drop_field(obj: &mut Map<String, Value>, field: &str, changes: &mut Changes) {
        if obj.remove(field).is_some() {
            changes.dropped.push(field.to_string());
        }
    }

    /// `/integrations/agent-group`: two renames and one removal.
    ///
    /// The proxy and reputation-source settings were regrouped under a
    /// common `networkSettings*` prefix in 2.5, and the malware-database
    /// URL was removed outright — 2.5 agents take it from the agent group's
    /// own update configuration instead.
    fn translate_agent_group(body: &mut Value) -> Changes {
        let mut changes = Changes::default();
        let Some(obj) = body.as_object_mut() else {
            return changes;
        };
        Self::rename(
            obj,
            "fileThreatProtectionProxyUrl",
            "networkSettingsProxyUrl",
            &mut changes,
        );
        Self::rename(
            obj,
            "networkReputationSource",
            "networkSettingsSource",
            &mut changes,
        );
        Self::drop_field(obj, "fileThreatProtectionMalwareDbUrl", &mut changes);
        changes
    }

    /// `/policies/assurance`: one rename and one removal.
    ///
    /// `failCICDStep` became `failExternalScansStep` when the check stopped
    /// being CI-specific. Inline custom controls were removed because 2.5
    /// promoted them to their own resource,
    /// `/policies/assurance-control`; both spellings seen in the wild
    /// (`customControls` on the detail endpoint, `CustomControls` on the
    /// list projection) are handled.
    fn translate_assurance_policy(body: &mut Value) -> Changes {
        let mut changes = Changes::default();
        let Some(obj) = body.as_object_mut() else {
            return changes;
        };
        Self::rename(obj, "failCICDStep", "failExternalScansStep", &mut changes);
        Self::drop_field(obj, "customControls", &mut changes);
        Self::drop_field(obj, "CustomControls", &mut changes);
        changes
    }

    /// `/policies/runtime-profile`: two renames, nested per rule.
    ///
    /// `APIv1` misspells two audit-event flags; `APIv3` fixes the spelling.
    /// They live inside `fileOperationsRules.items[].auditEvents`, so this
    /// is the only rule in the table that rewrites below the top level —
    /// and the only one where a profile with several rules can be
    /// partially translated if the walk is written carelessly.
    fn translate_runtime_profile(body: &mut Value) -> Changes {
        let mut changes = Changes::default();
        let Some(items) = body
            .get_mut("fileOperationsRules")
            .and_then(|r| r.get_mut("items"))
            .and_then(Value::as_array_mut)
        else {
            return changes;
        };

        for item in items.iter_mut() {
            let Some(events) = item.get_mut("auditEvents").and_then(Value::as_object_mut) else {
                continue;
            };
            // Recorded once per rule so the count reflects what was actually
            // rewritten; a profile with two rules reports two of each.
            Self::rename(events, "auditWritEvents", "auditWriteEvents", &mut changes);
            Self::rename(
                events,
                "auditRenameOrEvents",
                "auditRenameOrMoveEvents",
                &mut changes,
            );
        }
        changes
    }

    /// # Overview
    ///
    /// Splits an `APIv1` runtime policy into the two `APIv3` resources it
    /// became.
    ///
    /// Returns `(runtime_policy, admission_policy)`. The admission half is
    /// `None` when the source had no admission control in use — every
    /// `use*` flag false and every list empty — because a 2.4 instance
    /// that never enabled admission control should not leave a trail of
    /// empty policies on the 2.5 target.
    ///
    /// A no-op for a same-generation import: the runtime policy is
    /// returned unchanged and the admission half is `None`, since a v3
    /// bundle already carries its admission policies as their own
    /// resource.
    #[must_use]
    pub fn split_runtime_policy(&self, policy: &Value) -> (Value, Option<Value>) {
        if self.is_noop() {
            return (policy.clone(), None);
        }
        let Some(source) = policy.as_object() else {
            return (policy.clone(), None);
        };

        let mut runtime = Map::new();
        let mut admission = Map::new();

        for (key, value) in source {
            if ADMISSION_FIELDS.contains(&key.as_str()) {
                admission.insert(key.clone(), value.clone());
            } else {
                runtime.insert(key.clone(), value.clone());
            }
            // Shared fields are copied, not moved, so both halves keep them.
            if ADMISSION_SHARED_FIELDS.contains(&key.as_str()) {
                admission.insert(key.clone(), value.clone());
            }
        }

        if !Self::admission_is_in_use(&admission) {
            return (Value::Object(runtime), None);
        }
        (Value::Object(runtime), Some(Value::Object(admission)))
    }

    /// Whether an admission half is worth creating on the target.
    ///
    /// True when any `use*` flag is on, or any control list is non-empty.
    /// The list check matters independently of the flags: a policy can
    /// carry populated `bypassCriteria` with `useBypassCriteria` off, and
    /// discarding that content would quietly lose configuration the
    /// operator can see in the console.
    fn admission_is_in_use(admission: &Map<String, Value>) -> bool {
        admission.iter().any(|(key, value)| {
            if !ADMISSION_FIELDS.contains(&key.as_str()) {
                return false;
            }
            match value {
                Value::Bool(on) => *on,
                Value::Array(items) => !items.is_empty(),
                _ => false,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const V1_AGENT_GROUP: &str = include_str!("../tests/fixtures/v1/agent-group.json");
    const V1_ASSURANCE: &str = include_str!("../tests/fixtures/v1/assurance-policy.json");
    const V1_RUNTIME_PROFILE: &str = include_str!("../tests/fixtures/v1/runtime-profile.json");
    const V1_RUNTIME_POLICY: &str = include_str!("../tests/fixtures/v1/runtime-policy.json");
    const V1_RUNTIME_POLICY_BARE: &str =
        include_str!("../tests/fixtures/v1/runtime-policy-no-admission.json");

    fn fixture(raw: &str) -> Value {
        serde_json::from_str(raw).expect("fixture must be valid JSON")
    }

    /// The only translator the importer can legally build that does work.
    fn v1_to_v3() -> Translator {
        Translator::new(
            ApiVersion::V1,
            ApiVersion::V3,
            Some(KcsVersion::new(2, 4, 1)),
            Some(KcsVersion::new(2, 5, 0)),
        )
        .expect("v1 -> v3 is the supported direction")
    }

    fn keys(v: &Value) -> Vec<String> {
        v.as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default()
    }

    // ---- agent group ----

    #[test]
    fn agent_group_renames_proxy_and_reputation_source_and_drops_malware_db() {
        let mut body = fixture(V1_AGENT_GROUP);
        let changes = v1_to_v3().resource(Resource::AgentGroup, &mut body);

        // Renamed: new key present with the old value, old key gone.
        assert_eq!(
            body["networkSettingsProxyUrl"],
            json!("http://proxy.example.invalid:3128")
        );
        assert!(body.get("fileThreatProtectionProxyUrl").is_none());
        assert_eq!(body["networkSettingsSource"], json!("kcs-list"));
        assert!(body.get("networkReputationSource").is_none());

        // Dropped outright.
        assert!(body.get("fileThreatProtectionMalwareDbUrl").is_none());

        assert_eq!(
            changes.renamed,
            vec![
                (
                    "fileThreatProtectionProxyUrl".to_string(),
                    "networkSettingsProxyUrl".to_string()
                ),
                (
                    "networkReputationSource".to_string(),
                    "networkSettingsSource".to_string()
                ),
            ]
        );
        assert_eq!(changes.dropped, vec!["fileThreatProtectionMalwareDbUrl"]);
    }

    #[test]
    fn agent_group_translation_adds_no_v3_only_fields() {
        // The v3 additions (benchmarkScanTime, networkOtherConnectionDisabled,
        // orchestratorPlatform, resources, requireRedeployment) are left absent so
        // the target applies its own defaults. Inventing values here would quietly
        // configure a customer's agents.
        let mut body = fixture(V1_AGENT_GROUP);
        v1_to_v3().resource(Resource::AgentGroup, &mut body);
        for invented in [
            "benchmarkScanTime",
            "networkOtherConnectionDisabled",
            "resources",
            "requireRedeployment",
        ] {
            assert!(
                body.get(invented).is_none(),
                "translation must not invent {invented}"
            );
        }
    }

    #[test]
    fn agent_group_leaves_every_other_field_alone() {
        let before = fixture(V1_AGENT_GROUP);
        let mut after = before.clone();
        v1_to_v3().resource(Resource::AgentGroup, &mut after);

        let touched = [
            "fileThreatProtectionProxyUrl",
            "networkReputationSource",
            "fileThreatProtectionMalwareDbUrl",
            "networkSettingsProxyUrl",
            "networkSettingsSource",
        ];
        for key in keys(&before) {
            if touched.contains(&key.as_str()) {
                continue;
            }
            assert_eq!(before[&key], after[&key], "{key} should be untouched");
        }
    }

    // ---- assurance policy ----

    #[test]
    fn assurance_renames_fail_cicd_step_and_drops_custom_controls() {
        let mut body = fixture(V1_ASSURANCE);
        let changes = v1_to_v3().resource(Resource::AssurancePolicy, &mut body);

        assert_eq!(body["failExternalScansStep"], json!(true));
        assert!(body.get("failCICDStep").is_none());
        assert!(body.get("customControls").is_none());

        assert_eq!(
            changes.renamed,
            vec![(
                "failCICDStep".to_string(),
                "failExternalScansStep".to_string()
            )]
        );
        assert_eq!(changes.dropped, vec!["customControls"]);
    }

    #[test]
    fn assurance_handles_the_capitalised_spelling_from_the_list_endpoint() {
        // The detail endpoint returns `customControls`; the list projection
        // returns `CustomControls`. Both must go.
        let mut body = json!({"name": "p", "CustomControls": [{"id": "c1"}]});
        let changes = v1_to_v3().resource(Resource::AssurancePolicy, &mut body);
        assert!(body.get("CustomControls").is_none());
        assert_eq!(changes.dropped, vec!["CustomControls"]);
    }

    // ---- runtime profile: the nested renames ----

    #[test]
    fn runtime_profile_renames_both_audit_typos_in_every_rule() {
        let mut body = fixture(V1_RUNTIME_PROFILE);
        let changes = v1_to_v3().resource(Resource::RuntimeProfile, &mut body);

        let items = body["fileOperationsRules"]["items"]
            .as_array()
            .expect("fixture has two rules")
            .clone();
        assert_eq!(items.len(), 2, "both rules must survive the walk");

        // Rule 0 had both flags true; rule 1 had both false. The values must ride
        // across with the rename, not be reset to a default.
        assert_eq!(items[0]["auditEvents"]["auditWriteEvents"], json!(true));
        assert_eq!(
            items[0]["auditEvents"]["auditRenameOrMoveEvents"],
            json!(true)
        );
        assert_eq!(items[1]["auditEvents"]["auditWriteEvents"], json!(false));
        assert_eq!(
            items[1]["auditEvents"]["auditRenameOrMoveEvents"],
            json!(false)
        );

        for item in &items {
            let events = &item["auditEvents"];
            assert!(events.get("auditWritEvents").is_none());
            assert!(events.get("auditRenameOrEvents").is_none());
            // Sibling flags are untouched.
            assert!(events.get("auditOpenEvents").is_some());
            assert!(events.get("auditDeleteEvents").is_some());
        }

        // Two rules x two renames.
        assert_eq!(changes.renamed.len(), 4);
    }

    #[test]
    fn runtime_profile_without_file_operations_rules_is_untouched() {
        let mut body = json!({"name": "p", "useFileOperations": false});
        let before = body.clone();
        let changes = v1_to_v3().resource(Resource::RuntimeProfile, &mut body);
        assert_eq!(body, before);
        assert!(changes.is_empty());
    }

    // ---- the runtime policy split ----

    #[test]
    fn split_moves_all_sixteen_admission_fields_off_the_runtime_policy() {
        let source = fixture(V1_RUNTIME_POLICY);
        let (runtime, admission) = v1_to_v3().split_runtime_policy(&source);
        let admission = admission.expect("fixture has admission controls in use");

        for field in ADMISSION_FIELDS {
            assert!(
                runtime.get(field).is_none(),
                "{field} must not remain on the v3 runtime policy"
            );
            assert!(
                admission.get(field).is_some(),
                "{field} must appear on the admission policy"
            );
        }
    }

    #[test]
    fn split_keeps_runtime_only_fields_on_the_runtime_half() {
        let source = fixture(V1_RUNTIME_POLICY);
        let (runtime, _) = v1_to_v3().split_runtime_policy(&source);

        for field in [
            "type",
            "containerLifecycleEnabled",
            "containerLifecycleOperationTypes",
            "useContainerRuntimeProfiles",
            "runtimeProfileMatchBlocks",
            "useAutoProfiles",
        ] {
            assert!(runtime.get(field).is_some(), "{field} belongs to runtime");
        }
        // The profile match block, which later gets FK-rewritten, rides across intact.
        assert_eq!(
            runtime["runtimeProfileMatchBlocks"][0]["profileNames"][0],
            json!("example-profile")
        );
    }

    #[test]
    fn split_copies_the_shared_fields_onto_both_halves() {
        // `name` in particular: the live 2.5 instance pairs a runtime policy with
        // its admission counterpart by name, so losing it would break the pairing
        // an operator sees even though both resources were created.
        let source = fixture(V1_RUNTIME_POLICY);
        let (runtime, admission) = v1_to_v3().split_runtime_policy(&source);
        let admission = admission.expect("admission half expected");

        for field in ADMISSION_SHARED_FIELDS {
            assert_eq!(
                runtime.get(field),
                admission.get(field),
                "{field} must be copied to both halves, not moved"
            );
        }
        assert_eq!(admission["name"], json!("example-runtime"));
        assert_eq!(admission["enforcementMode"], json!("audit"));
    }

    #[test]
    fn split_returns_no_admission_half_when_nothing_is_in_use() {
        let source = fixture(V1_RUNTIME_POLICY_BARE);
        let (runtime, admission) = v1_to_v3().split_runtime_policy(&source);
        assert!(
            admission.is_none(),
            "a 2.4 source that never enabled admission control must not litter the \
             target with an empty policy"
        );
        assert!(runtime.get("useCapabilityBlock").is_none());
    }

    #[test]
    fn split_keeps_a_populated_list_even_when_its_flag_is_off() {
        // A policy can carry content with its flag disabled. Treating "all flags
        // false" as "nothing to migrate" would silently drop that content.
        let source = json!({
            "name": "flag-off-but-populated",
            "useBypassCriteria": false,
            "bypassCriteria": ["image.registry.example.invalid"],
            "useCapabilityBlock": false,
            "capabilityBlock": [],
        });
        let (_, admission) = v1_to_v3().split_runtime_policy(&source);
        let admission = admission.expect("a populated list is configuration worth keeping");
        assert_eq!(
            admission["bypassCriteria"][0],
            json!("image.registry.example.invalid")
        );
    }

    // ---- same-generation imports must be the identity ----

    #[test]
    fn same_generation_translation_changes_nothing() {
        for api in [ApiVersion::V1, ApiVersion::V3] {
            let t = Translator::new(api, api, None, None).expect("same generation is fine");
            assert!(t.is_noop());

            for (resource, raw) in [
                (Resource::AgentGroup, V1_AGENT_GROUP),
                (Resource::AssurancePolicy, V1_ASSURANCE),
                (Resource::RuntimeProfile, V1_RUNTIME_PROFILE),
                (Resource::RuntimePolicy, V1_RUNTIME_POLICY),
            ] {
                let before = fixture(raw);
                let mut after = before.clone();
                let changes = t.resource(resource, &mut after);
                assert_eq!(after, before, "{resource:?} must be untouched for {api:?}");
                assert!(changes.is_empty());
            }
        }
    }

    #[test]
    fn same_generation_split_returns_the_policy_unchanged() {
        // A v3 bundle already carries its admission policies as a separate
        // resource, so splitting again would duplicate them.
        let t = Translator::new(ApiVersion::V3, ApiVersion::V3, None, None).expect("v3 -> v3");
        let source = fixture(V1_RUNTIME_POLICY);
        let (runtime, admission) = t.split_runtime_policy(&source);
        assert_eq!(runtime, source);
        assert!(admission.is_none());
    }

    // ---- downgrade refusal ----

    #[test]
    fn downgrade_is_refused_at_construction() {
        let err = Translator::new(
            ApiVersion::V3,
            ApiVersion::V1,
            Some(KcsVersion::new(2, 5, 0)),
            Some(KcsVersion::new(2, 4, 1)),
        )
        .expect_err("v3 -> v1 must be refused");

        let rendered = err.to_string();
        assert!(rendered.contains("KCS 2.5.0"), "names the bundle release");
        assert!(rendered.contains("KCS 2.4.1"), "names the target release");
        assert!(
            rendered.contains("downgrade is not supported"),
            "says plainly what is wrong, got: {rendered}"
        );
    }

    #[test]
    fn downgrade_message_copes_with_unknown_releases() {
        // A format-1 bundle records no release, so the message must still read.
        let err = Translator::new(ApiVersion::V3, ApiVersion::V1, None, None)
            .expect_err("v3 -> v1 must be refused");
        assert!(err.to_string().contains("unknown version"));
    }

    #[test]
    fn upgrade_and_same_generation_are_all_accepted() {
        assert!(Translator::new(ApiVersion::V1, ApiVersion::V3, None, None).is_ok());
        assert!(Translator::new(ApiVersion::V1, ApiVersion::V1, None, None).is_ok());
        assert!(Translator::new(ApiVersion::V3, ApiVersion::V3, None, None).is_ok());
    }

    // ---- resources that must not drift ----

    #[test]
    fn image_registries_are_not_translated() {
        // The v3 OpenAPI document omits pullMode and repositoryPathMode, but the
        // live server returns both and the v1/v3 payloads are byte-identical.
        // Trusting the document here would have corrupted every registry.
        let mut body = json!({
            "registryName": "r",
            "pullMode": "all",
            "repositoryPathMode": "full",
            "scanTimeout": 600,
        });
        let before = body.clone();
        let changes = v1_to_v3().resource(Resource::ImageRegistry, &mut body);
        assert_eq!(body, before);
        assert!(changes.is_empty());
    }

    #[test]
    fn non_object_bodies_are_left_alone_rather_than_panicking() {
        // Bundles are editable by hand before import, so a malformed entry is
        // reachable input, not an impossible state.
        for mut body in [json!([1, 2, 3]), json!("a string"), json!(null)] {
            let before = body.clone();
            for resource in [
                Resource::AgentGroup,
                Resource::AssurancePolicy,
                Resource::RuntimeProfile,
            ] {
                let changes = v1_to_v3().resource(resource, &mut body);
                assert!(changes.is_empty());
            }
            assert_eq!(body, before);
            let (runtime, admission) = v1_to_v3().split_runtime_policy(&body);
            assert_eq!(runtime, before);
            assert!(admission.is_none());
        }
    }
}
