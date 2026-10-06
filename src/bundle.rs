//! # Overview
//!
//! The bundle's `manifest.json`: what produced it, when, from where, and
//! — new in format 2 — which API generation its bodies are shaped for.
//!
//! # Why the manifest is load-bearing now
//!
//! In format 1 the manifest was informational. In format 2 the importer
//! cannot work without it: [`crate::translate`] needs to know which
//! generation wrote the bundle in order to decide whether to translate,
//! and guessing wrong is silent. A v1 bundle replayed untranslated into
//! a 2.5 target sends `failCICDStep` to an endpoint that wants
//! `failExternalScansStep`, and the field is simply ignored.
//!
//! # Written last, on purpose
//!
//! [`crate::export::export_all`] writes `manifest.json` after every other
//! file. Its absence is therefore the marker of an interrupted export,
//! and [`Manifest::read`] refusing such a directory is what stops a
//! half-written bundle from being replayed onto a target.
//!
//! # Format 1 compatibility
//!
//! A manifest with no `bundle_format` key was written by 0.1.0, which
//! only ever spoke `APIv1`. Such a bundle is read as
//! [`ApiVersion::V1`] with no known release, rather than rejected —
//! people have bundles on disk already.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::version::{self, ApiVersion, KcsVersion};

/// Format version this build writes.
pub const BUNDLE_FORMAT: u32 = 2;

/// Manifest file name, relative to the bundle root.
pub const MANIFEST_FILE: &str = "manifest.json";

/// # Overview
///
/// A bundle's `manifest.json`, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// `CARGO_PKG_VERSION` of the migrator that produced the bundle.
    pub tool_version: String,
    /// Bundle layout version; 1 for anything written by 0.1.0.
    pub bundle_format: u32,
    /// UTC export timestamp, as it appears in the directory name.
    pub timestamp: String,
    /// Base URL the bundle was exported from.
    pub source_url: String,
    /// Release of the source instance, when it was recorded.
    pub kcs_version: Option<KcsVersion>,
    /// Generation the bundle's bodies are shaped for.
    pub api_version: ApiVersion,
}

impl Manifest {
    /// # Overview
    ///
    /// Builds a format-2 manifest for an export that just happened.
    #[must_use]
    pub fn new(
        tool_version: &str,
        timestamp: &str,
        source_url: &str,
        kcs_version: Option<KcsVersion>,
        api_version: ApiVersion,
    ) -> Self {
        Self {
            tool_version: tool_version.to_string(),
            bundle_format: BUNDLE_FORMAT,
            timestamp: timestamp.to_string(),
            source_url: source_url.to_string(),
            kcs_version,
            api_version,
        }
    }

    /// Serializes to the JSON written into the bundle.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "tool_version": self.tool_version,
            "bundle_format": self.bundle_format,
            "timestamp": self.timestamp,
            "source_url": self.source_url,
            // Recorded as the string the instance reported, so a human reading the
            // manifest sees what /healthz said rather than a re-rendered struct.
            "kcs_version": self.kcs_version.map(|v| v.to_string()),
            "api_version": self.api_version.prefix().trim_start_matches('/'),
        })
    }

    /// # Overview
    ///
    /// Reads and parses `<bundle>/manifest.json`.
    ///
    /// # Errors
    ///
    /// Returns an error naming the directory when the manifest is absent
    /// — which means the export did not finish, since the manifest is
    /// written last — or when it cannot be parsed.
    pub fn read(bundle: &Path) -> Result<Self> {
        let path = bundle.join(MANIFEST_FILE);
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "{} has no {MANIFEST_FILE}, so it is not a complete bundle. The manifest \
                 is written last, so its absence means the export was interrupted — \
                 re-run the export rather than importing a partial bundle.",
                bundle.display()
            ));
        }

        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let raw: Value = serde_json::from_str(&text)
            .with_context(|| format!("{} is not valid JSON", path.display()))?;

        let string_at = |key: &str| {
            raw.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };

        // No `bundle_format` key means 0.1.0 wrote it, and 0.1.0 only spoke APIv1.
        let bundle_format = raw
            .get("bundle_format")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(1);

        // Anything that is not explicitly v3 is read as v1. That folds three cases
        // together on purpose: an explicit "v1", a missing field (every bundle
        // predating it), and an unrecognised value such as "v2" — which exists on
        // the server but is not modelled, so there is nothing better to do than
        // assume the older shape and let the operator pin the target side with
        // --api-version if the pairing turns out wrong.
        let api_version = if raw.get("api_version").and_then(Value::as_str) == Some("v3") {
            ApiVersion::V3
        } else {
            ApiVersion::V1
        };

        let kcs_version = raw
            .get("kcs_version")
            .and_then(Value::as_str)
            .and_then(|s| version::parse(s).ok());

        Ok(Self {
            tool_version: string_at("tool_version"),
            bundle_format,
            timestamp: string_at("timestamp"),
            source_url: string_at("source_url"),
            kcs_version,
            api_version,
        })
    }

    /// Whether this bundle predates the format-2 layout.
    #[must_use]
    pub const fn is_legacy(&self) -> bool {
        self.bundle_format < BUNDLE_FORMAT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_manifest(dir: &Path, raw: &Value) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join(MANIFEST_FILE), serde_json::to_string(raw)?)?;
        Ok(())
    }

    #[test]
    fn a_format_2_manifest_round_trips() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let written = Manifest::new(
            "0.2.0",
            "2026-10-06_12-00-00",
            "https://kcs.demo.lab/api",
            Some(KcsVersion::new(2, 5, 0)),
            ApiVersion::V3,
        );
        write_manifest(tmp.path(), &written.to_json())?;

        let read = Manifest::read(tmp.path())?;
        assert_eq!(read, written);
        assert_eq!(read.bundle_format, 2);
        assert_eq!(read.api_version, ApiVersion::V3);
        assert_eq!(read.kcs_version, Some(KcsVersion::new(2, 5, 0)));
        assert!(!read.is_legacy());
        Ok(())
    }

    #[test]
    fn a_manifest_without_bundle_format_is_read_as_a_v1_format_1_bundle() -> Result<()> {
        // Exactly what 0.1.0 wrote. People have these on disk, so they must still
        // import, and 0.1.0 only ever spoke APIv1.
        let tmp = tempfile::tempdir()?;
        write_manifest(
            tmp.path(),
            &json!({
                "tool_version": "0.1.0",
                "timestamp": "2026-05-21_16-58-53",
                "source_url": "https://kcs.old.corp/api",
            }),
        )?;

        let read = Manifest::read(tmp.path())?;
        assert_eq!(read.bundle_format, 1);
        assert_eq!(read.api_version, ApiVersion::V1);
        assert_eq!(read.kcs_version, None, "0.1.0 did not record a release");
        assert_eq!(read.tool_version, "0.1.0");
        assert!(read.is_legacy());
        Ok(())
    }

    #[test]
    fn a_missing_manifest_is_an_error_that_explains_what_it_means() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = Manifest::read(tmp.path()).expect_err("no manifest must fail");
        let rendered = format!("{err}");
        assert!(
            rendered.contains(&tmp.path().display().to_string()),
            "names the directory"
        );
        assert!(
            rendered.contains("written last"),
            "says why absence means interrupted, got: {rendered}"
        );
    }

    #[test]
    fn a_malformed_manifest_is_an_error_not_a_default() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        std::fs::write(tmp.path().join(MANIFEST_FILE), "{not json")?;
        let err = Manifest::read(tmp.path()).expect_err("bad JSON must fail");
        assert!(format!("{err}").contains("not valid JSON"));
        Ok(())
    }

    #[test]
    fn an_unrecognised_api_version_falls_back_to_v1() -> Result<()> {
        // v2 exists on the server but the tool does not model it. Falling back to
        // v1 matches what every bundle predating the field was; the operator can
        // still pin the target side with --api-version.
        let tmp = tempfile::tempdir()?;
        write_manifest(
            tmp.path(),
            &json!({"bundle_format": 2, "api_version": "v2"}),
        )?;
        assert_eq!(Manifest::read(tmp.path())?.api_version, ApiVersion::V1);
        Ok(())
    }

    #[test]
    fn an_unparseable_kcs_version_is_dropped_rather_than_failing_the_read() -> Result<()> {
        // The release is only used for an error message, so a weird value must not
        // stop an otherwise good bundle from importing.
        let tmp = tempfile::tempdir()?;
        write_manifest(
            tmp.path(),
            &json!({"bundle_format": 2, "api_version": "v3", "kcs_version": "2.5"}),
        )?;
        let read = Manifest::read(tmp.path())?;
        assert_eq!(read.kcs_version, None);
        assert_eq!(read.api_version, ApiVersion::V3);
        Ok(())
    }

    #[test]
    fn kcs_version_is_recorded_as_the_string_the_instance_reported() {
        let m = Manifest::new(
            "0.2.0",
            "t",
            "u",
            Some(KcsVersion::new(2, 5, 1)),
            ApiVersion::V3,
        );
        assert_eq!(m.to_json()["kcs_version"], json!("2.5.1"));
        assert_eq!(m.to_json()["api_version"], json!("v3"));
    }

    #[test]
    fn an_unknown_release_serialises_as_null_not_a_placeholder_string() {
        let m = Manifest::new("0.2.0", "t", "u", None, ApiVersion::V1);
        assert_eq!(m.to_json()["kcs_version"], Value::Null);
    }
}
