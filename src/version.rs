//! # Overview
//!
//! Which generation of the KCS REST API to speak, and how to work that
//! out from the instance itself.
//!
//! A KCS server exposes several API generations side by side under
//! `/api/v1/`, `/api/v2/` and `/api/v3/`. KCS 2.4 and earlier only have
//! `v1`; 2.5 introduced `v3` and keeps `v1` as a compatibility shim; 2.6
//! deprecates `v1`. The migrator therefore has to pick a generation per
//! instance rather than hard-coding one.
//!
//! `GET /api/{v}/healthz` answers `{"version":"2.5.0"}` on every
//! generation, which makes it the detection probe. This module owns the
//! pure half of that: parsing the string, reading it out of a decoded
//! body, and mapping a release to an API generation.
//! [`crate::client::KcsClient`] owns the HTTP half.
//!
//! `v2` is deliberately not modelled. It exists on the server but no
//! product documentation references it, so there is no basis for
//! choosing it over `v1` or `v3`.

use serde_json::Value;
use thiserror::Error;

/// First KCS release that serves `APIv3`.
const FIRST_V3_RELEASE: KcsVersion = KcsVersion {
    major: 2,
    minor: 5,
    patch: 0,
};

/// # Overview
///
/// Failures from reading or parsing a KCS version.
///
/// This is a `thiserror` enum rather than an [`anyhow::Error`] because
/// the detection path in [`crate::client::KcsClient`] *matches* on
/// [`VersionError::Undetectable`] to decide whether to fall through to
/// the next probe. An `anyhow::Error` would erase the variant and force
/// the caller to match on message text.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VersionError {
    /// The string was not three dot-separated components.
    #[error("KCS version string {0:?} is not MAJOR.MINOR.PATCH")]
    Malformed(String),

    /// One of the three components was not a decimal number.
    #[error("KCS version component {component:?} in {input:?} is not a number")]
    NotANumber {
        /// The whole string, for context in the message.
        input: String,
        /// The offending component.
        component: String,
    },

    /// A `healthz` body arrived but carried no usable `version` field.
    #[error("healthz response has no string `version` field")]
    NoVersionField,

    /// No probe produced a version at all.
    #[error(
        "could not determine the KCS version: neither /v1/healthz nor /v3/healthz \
         answered with a version field. Pass --api-version v1|v3 to skip detection."
    )]
    Undetectable,
}

/// # Overview
///
/// A `MAJOR.MINOR.PATCH` KCS release, as reported by `GET /{v}/healthz`.
///
/// `Ord` is derived, which makes `v < FIRST_V3_RELEASE` the whole version
/// gate. **The field declaration order is load-bearing**: a derived `Ord`
/// compares fields top to bottom, so `major`, `minor`, `patch` in that
/// order is what makes the comparison mean what it reads like. Reordering
/// them would silently invert it.
///
/// Comparing the version *strings* instead would be wrong for the same
/// reason: `"2.10.0" < "2.5.0"` lexicographically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KcsVersion {
    /// Major release.
    pub major: u32,
    /// Minor release.
    pub minor: u32,
    /// Patch release.
    pub patch: u32,
}

impl KcsVersion {
    /// # Overview
    ///
    /// Builds a version from its three components. Mostly a convenience
    /// for tests and for the module's own version-boundary constant.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl std::fmt::Display for KcsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// # Overview
///
/// Which generation of the KCS REST API to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiVersion {
    /// `/api/v1/` — KCS 2.4 and earlier, and the 2.5 compatibility shim.
    V1,
    /// `/api/v3/` — KCS 2.5 and later.
    V3,
}

impl ApiVersion {
    /// # Overview
    ///
    /// Path prefix this generation's endpoints live under, e.g. `"/v3"`.
    ///
    /// Takes `self` by value: `ApiVersion` is `Copy` and one
    /// discriminant wide, so a `&self` here would be strictly more
    /// indirection for nothing (`clippy::trivially_copy_pass_by_ref`).
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::V1 => "/v1",
            Self::V3 => "/v3",
        }
    }

    /// # Overview
    ///
    /// The API generation to use against a given KCS release: `APIv1`
    /// below 2.5.0, `APIv3` from 2.5.0 on.
    ///
    /// # Examples
    ///
    /// ```
    /// use kcs_migrator::version::{ApiVersion, KcsVersion};
    ///
    /// assert_eq!(ApiVersion::for_kcs(KcsVersion::new(2, 4, 9)), ApiVersion::V1);
    /// assert_eq!(ApiVersion::for_kcs(KcsVersion::new(2, 5, 0)), ApiVersion::V3);
    ///
    /// // Numeric, not lexicographic: "2.10.0" sorts before "2.5.0" as text.
    /// assert_eq!(ApiVersion::for_kcs(KcsVersion::new(2, 10, 0)), ApiVersion::V3);
    /// ```
    #[must_use]
    pub fn for_kcs(version: KcsVersion) -> Self {
        if version < FIRST_V3_RELEASE {
            Self::V1
        } else {
            Self::V3
        }
    }
}

/// # Overview
///
/// Parses a `MAJOR.MINOR.PATCH` KCS version string.
///
/// Strict by design: exactly three components, decimal digits only, no
/// `v` prefix and no trailing build metadata. The string comes from one
/// vendor endpoint with one documented shape, so anything else means the
/// assumption has broken and the operator should hear about it rather
/// than get a silently wrong API generation.
///
/// # Errors
///
/// [`VersionError::Malformed`] when the component count is not three,
/// [`VersionError::NotANumber`] when a component is not a decimal number.
///
/// # Examples
///
/// ```
/// use kcs_migrator::version::{self, KcsVersion};
///
/// assert_eq!(version::parse("2.5.0")?, KcsVersion::new(2, 5, 0));
///
/// // Strict on purpose: a vendor endpoint emits one documented shape, so
/// // anything else means the assumption broke and the operator should hear
/// // about it rather than get a silently wrong API generation.
/// assert!(version::parse("2.5").is_err());
/// assert!(version::parse("v2.5.0").is_err());
/// assert!(version::parse("2.5.0-rc1").is_err());
/// # Ok::<(), version::VersionError>(())
/// ```
pub fn parse(s: &str) -> Result<KcsVersion, VersionError> {
    let mut parts = s.split('.');
    // `next()` three times plus an exhausted check, rather than `collect()` into a
    // `Vec`: it needs no allocation, and the slice pattern over a collected `Vec`
    // would not distinguish "too few" from "too many" without a length test anyway.
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VersionError::Malformed(s.to_string()));
    };

    let number = |component: &str| {
        component
            .parse::<u32>()
            .map_err(|_| VersionError::NotANumber {
                input: s.to_string(),
                component: component.to_string(),
            })
    };

    Ok(KcsVersion::new(
        number(major)?,
        number(minor)?,
        number(patch)?,
    ))
}

/// # Overview
///
/// Reads the version out of a decoded `GET /{v}/healthz` body, which
/// looks like `{"version":"2.5.0"}`.
///
/// Split from the HTTP call so the version-selection logic is testable
/// without a transport.
///
/// # Errors
///
/// [`VersionError::NoVersionField`] when `version` is absent or not a
/// string; otherwise whatever [`parse`] returns.
///
/// # Examples
///
/// ```
/// use kcs_migrator::version::{self, KcsVersion};
/// use serde_json::json;
///
/// // The exact body a live KCS 2.5.0 instance returns.
/// let body = json!({"version": "2.5.0"});
/// assert_eq!(version::from_healthz_body(&body)?, KcsVersion::new(2, 5, 0));
/// # Ok::<(), version::VersionError>(())
/// ```
pub fn from_healthz_body(body: &Value) -> Result<KcsVersion, VersionError> {
    let raw = body
        .get("version")
        .and_then(Value::as_str)
        .ok_or(VersionError::NoVersionField)?;
    parse(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_well_formed_version() {
        assert_eq!(parse("2.5.0"), Ok(KcsVersion::new(2, 5, 0)));
        assert_eq!(parse("2.4.1"), Ok(KcsVersion::new(2, 4, 1)));
        assert_eq!(parse("10.20.30"), Ok(KcsVersion::new(10, 20, 30)));
    }

    #[test]
    fn rejects_malformed_component_counts() {
        for bad in ["", "2", "2.5", "2.5.0.1", "..", "2.5."] {
            match parse(bad) {
                Err(VersionError::Malformed(_) | VersionError::NotANumber { .. }) => {}
                other => panic!("{bad:?} should not parse, got {other:?}"),
            }
        }
        // The component count, specifically, is what these two get wrong.
        assert_eq!(parse("2.5"), Err(VersionError::Malformed("2.5".into())));
        assert_eq!(
            parse("2.5.0.1"),
            Err(VersionError::Malformed("2.5.0.1".into()))
        );
    }

    #[test]
    fn rejects_non_numeric_components() {
        assert_eq!(
            parse("v2.5.0"),
            Err(VersionError::NotANumber {
                input: "v2.5.0".into(),
                component: "v2".into(),
            })
        );
        assert_eq!(
            parse("2.x.0"),
            Err(VersionError::NotANumber {
                input: "2.x.0".into(),
                component: "x".into(),
            })
        );
        // No signs, no whitespace, no trailing metadata.
        assert!(parse("2.-5.0").is_err());
        assert!(parse("2. 5.0").is_err());
        assert!(parse("2.5.0-rc1").is_err());
    }

    #[test]
    fn api_version_gate_is_at_exactly_2_5_0() {
        // Below the boundary.
        for v in [
            KcsVersion::new(1, 2, 2),
            KcsVersion::new(2, 4, 0),
            KcsVersion::new(2, 4, 9),
            KcsVersion::new(2, 4, 999),
        ] {
            assert_eq!(ApiVersion::for_kcs(v), ApiVersion::V1, "{v} should be V1");
        }
        // The boundary itself, and above. 2.5.0 is the release that introduced v3,
        // so an off-by-one here picks the wrong API for every 2.5.0 customer.
        for v in [
            KcsVersion::new(2, 5, 0),
            KcsVersion::new(2, 5, 1),
            KcsVersion::new(2, 6, 0),
            KcsVersion::new(3, 0, 0),
        ] {
            assert_eq!(ApiVersion::for_kcs(v), ApiVersion::V3, "{v} should be V3");
        }
    }

    #[test]
    fn version_ordering_is_numeric_not_lexicographic() {
        assert!(KcsVersion::new(2, 4, 9) < KcsVersion::new(2, 5, 0));
        // The case that string comparison gets wrong: "2.10.0" < "2.5.0" as text.
        assert!(KcsVersion::new(2, 5, 0) < KcsVersion::new(2, 10, 0));
        assert!(KcsVersion::new(2, 5, 0) < KcsVersion::new(2, 5, 1));
        assert!(KcsVersion::new(1, 99, 99) < KcsVersion::new(2, 0, 0));
        // And the gate built on that ordering agrees.
        assert_eq!(
            ApiVersion::for_kcs(KcsVersion::new(2, 10, 0)),
            ApiVersion::V3
        );
    }

    #[test]
    fn prefixes_are_the_api_path_segments() {
        assert_eq!(ApiVersion::V1.prefix(), "/v1");
        assert_eq!(ApiVersion::V3.prefix(), "/v3");
    }

    #[test]
    fn reads_version_from_a_healthz_body() {
        // The exact body shape returned by the live 2.5.0 instance.
        assert_eq!(
            from_healthz_body(&json!({"version": "2.5.0"})),
            Ok(KcsVersion::new(2, 5, 0))
        );
    }

    #[test]
    fn healthz_body_without_a_version_field_is_an_error() {
        for body in [json!({}), json!({"version": 250}), json!({"status": "ok"})] {
            assert_eq!(
                from_healthz_body(&body),
                Err(VersionError::NoVersionField),
                "{body} should have no usable version"
            );
        }
    }

    #[test]
    fn undetectable_message_names_the_override_flag() {
        // The message is the only thing the operator sees when detection fails, so
        // the flag that rescues them has to be in it.
        let rendered = VersionError::Undetectable.to_string();
        assert!(
            rendered.contains("--api-version"),
            "message must name the override flag, got: {rendered}"
        );
    }

    #[test]
    fn display_round_trips_through_parse() {
        let v = KcsVersion::new(2, 5, 1);
        assert_eq!(parse(&v.to_string()), Ok(v));
    }
}
