//! # Overview
//!
//! In-memory registry that maps a source KCS instance's resource IDs
//! to the IDs assigned by the target instance when the bundle is
//! replayed. The [`crate::importer`] populates the registry as it
//! creates resources (image registries, agent groups, policies, …) and
//! consults it later when rewriting foreign-key fields on downstream
//! resources (e.g. a runtime policy's `runtimeProfileId`).
//!
//! Resource types are namespaced by string so a single mapper can hold
//! mappings for many resource kinds without collision.

use std::collections::HashMap;
use thiserror::Error;

/// # Overview
///
/// Failures returned by [`IdMapper::resolve`] when an FK rewrite has
/// no entry to substitute. Both variants are reported up as
/// [`anyhow::Error`] by the importer with additional context (the
/// owning policy's name and the missing ID).
#[derive(Error, Debug, PartialEq)]
pub enum MapperError {
    /// The resource type has no entries registered yet — usually means
    /// the dependency-order step that creates this kind of resource
    /// has not run, or has not registered anything.
    #[error("No mappings registered for resource type '{0}'")]
    UnknownType(String),
    /// The resource type has entries, but the specific `source_id`
    /// being looked up was never registered. Indicates the source
    /// resource was deleted or not present in the bundle.
    #[error("Source ID '{source_id}' not mapped for resource type '{resource_type}'")]
    UnknownId {
        resource_type: String,
        source_id: String,
    },
}

/// # Overview
///
/// Two-level map of `resource_type` → `source_id` → `target_id`. Used
/// during import to translate cross-resource references from the
/// source instance's ID space into the target instance's ID space.
#[derive(Debug, Default)]
pub struct IdMapper {
    map: HashMap<String, HashMap<String, String>>,
}

impl IdMapper {
    /// # Overview
    ///
    /// Constructs an empty mapper. Equivalent to
    /// [`IdMapper::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// # Overview
    ///
    /// Records that the source instance's `source_id` for
    /// `resource_type` corresponds to `target_id` on the target
    /// instance. Re-registering the same `(resource_type, source_id)`
    /// pair overwrites the previous mapping.
    pub fn register(&mut self, resource_type: &str, source_id: &str, target_id: &str) {
        self.map
            .entry(resource_type.to_string())
            .or_default()
            .insert(source_id.to_string(), target_id.to_string());
    }

    /// # Overview
    ///
    /// Looks up the target ID previously registered for
    /// `(resource_type, source_id)`.
    ///
    /// # Errors
    ///
    /// Returns [`MapperError::UnknownType`] if no resource of that type
    /// has been registered yet, or [`MapperError::UnknownId`] if
    /// `source_id` was never registered. The importer aborts the
    /// import on either error rather than silently dropping the FK.
    pub fn resolve(&self, resource_type: &str, source_id: &str) -> Result<&str, MapperError> {
        let type_map = self
            .map
            .get(resource_type)
            .ok_or_else(|| MapperError::UnknownType(resource_type.to_string()))?;
        type_map
            .get(source_id)
            .map(|s| s.as_str())
            .ok_or_else(|| MapperError::UnknownId {
                resource_type: resource_type.to_string(),
                source_id: source_id.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn register_and_resolve() -> Result<()> {
        let mut m = IdMapper::new();
        m.register("runtime-profile", "src-001", "tgt-999");
        assert_eq!(m.resolve("runtime-profile", "src-001")?, "tgt-999");
        Ok(())
    }

    #[test]
    fn resolve_unknown_id_returns_err() {
        let m = IdMapper::new();
        assert!(matches!(
            m.resolve("runtime-profile", "nonexistent"),
            Err(MapperError::UnknownType(_))
        ));
    }

    #[test]
    fn resolve_unknown_source_id_returns_err() {
        let mut m = IdMapper::new();
        m.register("runtime-profile", "src-001", "tgt-999");
        assert!(matches!(
            m.resolve("runtime-profile", "bad-id"),
            Err(MapperError::UnknownId { .. })
        ));
    }

    #[test]
    fn multiple_resource_types_are_independent() -> Result<()> {
        let mut m = IdMapper::new();
        m.register("runtime-profile", "id-A", "id-X");
        m.register("scanner-policy", "id-A", "id-Y");
        assert_eq!(m.resolve("runtime-profile", "id-A")?, "id-X");
        assert_eq!(m.resolve("scanner-policy", "id-A")?, "id-Y");
        Ok(())
    }
}
