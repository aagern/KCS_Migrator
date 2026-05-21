use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum MapperError {
    #[error("No mappings registered for resource type '{0}'")]
    UnknownType(String),
    #[error("Source ID '{source_id}' not mapped for resource type '{resource_type}'")]
    UnknownId {
        resource_type: String,
        source_id: String,
    },
}

#[derive(Debug)]
pub struct IdMapper {
    map: HashMap<String, HashMap<String, String>>,
}

impl IdMapper {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn register(&mut self, resource_type: &str, source_id: &str, target_id: &str) {
        self.map
            .entry(resource_type.to_string())
            .or_default()
            .insert(source_id.to_string(), target_id.to_string());
    }

    pub fn resolve(&self, resource_type: &str, source_id: &str) -> Result<&str, MapperError> {
        let type_map = self.map.get(resource_type).ok_or_else(|| {
            MapperError::UnknownType(resource_type.to_string())
        })?;
        type_map.get(source_id).map(|s| s.as_str()).ok_or_else(|| MapperError::UnknownId {
            resource_type: resource_type.to_string(),
            source_id: source_id.to_string(),
        })
    }

    pub fn rewrite_ids(
        &self,
        body: &mut serde_json::Value,
        field: &str,
        resource_type: &str,
    ) -> Result<(), MapperError> {
        let ids: Vec<String> = body[field]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        let mut rewritten = Vec::with_capacity(ids.len());
        for id in &ids {
            rewritten.push(self.resolve(resource_type, id)?.to_string());
        }

        body[field] = serde_json::json!(rewritten);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn register_and_resolve() {
        let mut m = IdMapper::new();
        m.register("runtime-profile", "src-001", "tgt-999");
        assert_eq!(m.resolve("runtime-profile", "src-001").unwrap(), "tgt-999");
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
    fn rewrite_ids_list_field() {
        let mut m = IdMapper::new();
        m.register("notification", "n-1", "n-100");
        m.register("notification", "n-2", "n-200");
        let mut body = json!({"notificationSettingsIds": ["n-1", "n-2"]});
        m.rewrite_ids(&mut body, "notificationSettingsIds", "notification")
            .unwrap();
        assert_eq!(
            body["notificationSettingsIds"],
            json!(["n-100", "n-200"])
        );
    }

    #[test]
    fn rewrite_ids_does_not_mutate_unrelated_fields() {
        let mut m = IdMapper::new();
        m.register("notification", "n-1", "n-100");
        let mut body = json!({"notificationSettingsIds": ["n-1"], "name": "keep-me"});
        m.rewrite_ids(&mut body, "notificationSettingsIds", "notification")
            .unwrap();
        assert_eq!(body["name"], json!("keep-me"));
    }

    #[test]
    fn multiple_resource_types_are_independent() {
        let mut m = IdMapper::new();
        m.register("runtime-profile", "id-A", "id-X");
        m.register("scanner-policy", "id-A", "id-Y");
        assert_eq!(m.resolve("runtime-profile", "id-A").unwrap(), "id-X");
        assert_eq!(m.resolve("scanner-policy", "id-A").unwrap(), "id-Y");
    }
}
