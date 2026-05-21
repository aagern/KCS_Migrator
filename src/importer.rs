use crate::client::KcsClient;
use crate::id_mapper::IdMapper;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::path::Path;

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

fn read_json(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub async fn import_bundle(client: &KcsClient, bundle: &Path) -> Result<IdMapper> {
    let mut mapper = IdMapper::new();

    // 1. Reports storage config
    let reports_storage = read_json(&bundle.join("config/reports-storage.json"))?;
    if reports_storage.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        client.put_json("/v1/reports/storage/config", &reports_storage).await?;
    }

    // 2. Scanner priority
    let scanner_priority = read_json(&bundle.join("components/scanner-priority.json"))?;
    if scanner_priority.get("controls").and_then(|c| c.as_array()).map(|a| !a.is_empty()).unwrap_or(false) {
        client.post("/v1/scanners/priority", &scanner_priority).await?;
    }

    // 3. LDAP
    let ldap_raw = read_json(&bundle.join("integrations/ldap.json"))?;
    let ldap_data = if let Some(arr) = ldap_raw.as_array() {
        arr.first().cloned().unwrap_or(Value::Object(Default::default()))
    } else {
        ldap_raw
    };
    if ldap_data.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        client.put_json("/v1/integrations/ldap", &strip(&ldap_data)).await?;
    }

    // 4. SSO
    let sso = read_json(&bundle.join("integrations/sso.json"))?;
    if sso.get("clientId").is_some() {
        client.post("/v1/integrations/sso", &strip(&sso)).await?;
    }

    // 5. LLM
    let llm = read_json(&bundle.join("integrations/llm.json"))?;
    if llm.get("type").is_some() {
        client.post("/v1/integrations/llm", &strip(&llm)).await?;
    }

    // 6. Image registries
    let registries = read_json(&bundle.join("integrations/image-registries.json"))?;
    if let Some(arr) = registries.as_array() {
        for reg in arr {
            let src_id = reg["id"].as_str().unwrap_or("").to_string();
            let result = client.post("/v1/integrations/image-registries", &strip(reg)).await?;
            let tgt_id = result["id"].as_str().unwrap_or("").to_string();
            mapper.register("image-registry", &src_id, &tgt_id);
        }
    }

    // 7. Agent groups
    let agent_groups = read_json(&bundle.join("integrations/agent-groups.json"))?;
    if let Some(arr) = agent_groups.as_array() {
        for group in arr {
            let src_id = group["id"].as_str().unwrap_or("").to_string();
            let result = client.post("/v1/integrations/agent-group", &strip(group)).await?;
            let tgt_id = result["id"].as_str().unwrap_or("").to_string();
            mapper.register("agent-group", &src_id, &tgt_id);
        }
    }

    // 8. Scanner policies
    let scanner_policies = read_json(&bundle.join("policies/scanner.json"))?;
    if let Some(arr) = scanner_policies.as_array() {
        for pol in arr {
            let src_id = pol["id"].as_str().unwrap_or("").to_string();
            let enabled = pol["enabled"].as_bool().unwrap_or(false);
            let result = client.post("/v1/policies/scanner", &strip(pol)).await?;
            let tgt_id = result["id"].as_str().unwrap_or("").to_string();
            mapper.register("scanner-policy", &src_id, &tgt_id);
            if enabled {
                client.post(&format!("/v1/policies/scanner/{tgt_id}/enable"), &serde_json::json!({})).await?;
            }
        }
    }

    // 9. Assurance policies
    let assurance_policies = read_json(&bundle.join("policies/assurance.json"))?;
    if let Some(arr) = assurance_policies.as_array() {
        for pol in arr {
            let src_id = pol["id"].as_str().unwrap_or("").to_string();
            let enabled = pol["enabled"].as_bool().unwrap_or(false);
            let result = client.post("/v1/policies/assurance", &strip(pol)).await?;
            let tgt_id = result["id"].as_str().unwrap_or("").to_string();
            mapper.register("assurance-policy", &src_id, &tgt_id);
            if enabled {
                client.post(&format!("/v1/policies/assurance/{tgt_id}/enable"), &serde_json::json!({})).await?;
            }
        }
    }

    // 10. Runtime profiles
    let runtime_profiles = read_json(&bundle.join("policies/runtime-profiles.json"))?;
    if let Some(arr) = runtime_profiles.as_array() {
        for profile in arr {
            let src_id = profile["id"].as_str().unwrap_or("").to_string();
            let result = client.post("/v1/policies/runtime-profile", &strip(profile)).await?;
            let tgt_id = result["id"].as_str().unwrap_or("").to_string();
            mapper.register("runtime-profile", &src_id, &tgt_id);
        }
    }

    // 11. Runtime policies (rewrite runtimeProfileId)
    let runtime_policies = read_json(&bundle.join("policies/runtime.json"))?;
    if let Some(arr) = runtime_policies.as_array() {
        for pol in arr {
            let src_id = pol["id"].as_str().unwrap_or("").to_string();
            let enabled = pol["enabled"].as_bool().unwrap_or(false);
            let mut body = strip(pol);

            if let Some(blocks) = body.get("runtimeProfileMatchBlocks").and_then(|b| b.as_array()).cloned() {
                let mut rewritten = Vec::new();
                for mut block in blocks {
                    if let Some(old_id) = block.get("runtimeProfileId").and_then(|v| v.as_str()) {
                        let new_id = mapper.resolve("runtime-profile", old_id).map_err(|_| {
                            anyhow!(
                                "Runtime policy '{}' references runtime profile ID '{}' \
                                 that was not registered during import.",
                                pol.get("name").and_then(|n| n.as_str()).unwrap_or(&src_id),
                                old_id
                            )
                        })?;
                        block["runtimeProfileId"] = Value::String(new_id.to_string());
                    }
                    rewritten.push(block);
                }
                body["runtimeProfileMatchBlocks"] = Value::Array(rewritten);
            }

            let result = client.post("/v1/policies/runtime", &body).await?;
            let tgt_id = result["id"].as_str().unwrap_or("").to_string();
            mapper.register("runtime-policy", &src_id, &tgt_id);
            if enabled {
                client.post(&format!("/v1/policies/runtime/{tgt_id}/enable"), &serde_json::json!({})).await?;
            }
        }
    }

    // 12. Notification channels — reference only, warn
    let notif_ref = read_json(&bundle.join("integrations/notifications-REFERENCE.json"))?;
    let email_count = notif_ref["email"].as_array().map(|a| a.len()).unwrap_or(0);
    let tg_count = notif_ref["telegram"].as_array().map(|a| a.len()).unwrap_or(0);
    let wh_count = notif_ref["webhook"].as_array().map(|a| a.len()).unwrap_or(0);
    if email_count + tg_count + wh_count > 0 {
        eprintln!(
            "OPERATOR ACTION REQUIRED: Notification channels cannot be imported automatically.\n\
             Please manually recreate:\n  email: {email_count}\n  telegram: {tg_count}\n  webhook: {wh_count}"
        );
    }

    // 13. Response policies
    let response_policies = read_json(&bundle.join("policies/response.json"))?;
    if let Some(arr) = response_policies.as_array() {
        for pol in arr {
            let src_id = pol["id"].as_str().unwrap_or("").to_string();
            let enabled = pol["enabled"].as_bool().unwrap_or(false);
            let mut body = strip(pol);

            if let Some(notif_ids) = body.get("notificationSettingsIds").and_then(|v| v.as_array()).cloned() {
                let mut mapped = Vec::new();
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
                        pol.get("name").and_then(|n| n.as_str()).unwrap_or(&src_id),
                        unmapped
                    ));
                }
                body["notificationSettingsIds"] = Value::Array(mapped);
            }

            let result = client.post("/v1/policies/response", &body).await?;
            let tgt_id = result["id"].as_str().unwrap_or("").to_string();
            mapper.register("response-policy", &src_id, &tgt_id);
            if enabled {
                client.post(&format!("/v1/policies/response/{tgt_id}/enable"), &serde_json::json!({})).await?;
            }
        }
    }

    // 14. Network reputation binary
    let netrep_path = bundle.join("policies/network-reputation.bin");
    if netrep_path.exists() {
        let data = std::fs::read(&netrep_path)?;
        if !data.is_empty() {
            client.put_bytes("/v1/policies/custom-reputation/import", data).await?;
        }
    }

    Ok(mapper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_bundle(tmp: &tempfile::TempDir) -> std::path::PathBuf {
        let bundle = tmp.path().join("kcs-export-2026-01-01_00-00-00");
        std::fs::create_dir_all(bundle.join("integrations")).unwrap();
        std::fs::create_dir_all(bundle.join("policies")).unwrap();
        std::fs::create_dir_all(bundle.join("components")).unwrap();
        std::fs::create_dir_all(bundle.join("config")).unwrap();

        let write = |rel: &str, val: &Value| {
            std::fs::write(bundle.join(rel), serde_json::to_string(val).unwrap()).unwrap();
        };

        write("manifest.json", &json!({"tool_version": "0.1.0"}));
        write("integrations/image-registries.json", &json!([]));
        write("integrations/ldap.json", &json!([]));
        write("integrations/sso.json", &json!({}));
        write("integrations/llm.json", &json!({}));
        write("integrations/agent-groups.json", &json!([]));
        write("integrations/notifications-REFERENCE.json", &json!({"email":[],"telegram":[],"webhook":[]}));
        write("policies/scanner.json", &json!([]));
        write("policies/assurance.json", &json!([]));
        write("policies/runtime-profiles.json", &json!([]));
        write("policies/runtime.json", &json!([]));
        write("policies/response.json", &json!([]));
        write("components/scanner-priority.json", &json!({}));
        write("config/reports-storage.json", &json!({}));

        bundle
    }

    #[tokio::test]
    async fn import_scanner_policy_creates_and_enables() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = make_bundle(&tmp);
        std::fs::write(
            bundle.join("policies/scanner.json"),
            serde_json::to_string(&json!([
                {"id": "pol-src-1", "name": "My Scanner", "enabled": true, "useMalware": true}
            ])).unwrap(),
        ).unwrap();

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

        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let mapper = import_bundle(&client, &bundle).await.unwrap();
        assert_eq!(mapper.resolve("scanner-policy", "pol-src-1").unwrap(), "pol-tgt-99");
    }

    #[tokio::test]
    async fn import_runtime_policy_rewrites_profile_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = make_bundle(&tmp);
        std::fs::write(
            bundle.join("policies/runtime-profiles.json"),
            serde_json::to_string(&json!([{"id": "rp-src-1", "name": "Profile A"}])).unwrap(),
        ).unwrap();
        std::fs::write(
            bundle.join("policies/runtime.json"),
            serde_json::to_string(&json!([{
                "id": "rt-src-1", "name": "Runtime Policy", "enabled": false,
                "runtimeProfileMatchBlocks": [{"runtimeProfileId": "rp-src-1", "namespacePattern": "*"}]
            }])).unwrap(),
        ).unwrap();

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

        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let mapper = import_bundle(&client, &bundle).await.unwrap();
        assert_eq!(mapper.resolve("runtime-profile", "rp-src-1").unwrap(), "rp-tgt-1");
        assert_eq!(mapper.resolve("runtime-policy", "rt-src-1").unwrap(), "rt-tgt-1");
    }

    #[tokio::test]
    async fn import_runtime_policy_errors_on_unmapped_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = make_bundle(&tmp);
        std::fs::write(
            bundle.join("policies/runtime.json"),
            serde_json::to_string(&json!([{
                "id": "rt-src-1", "name": "Broken", "enabled": false,
                "runtimeProfileMatchBlocks": [{"runtimeProfileId": "rp-ghost-99"}]
            }])).unwrap(),
        ).unwrap();

        let server = MockServer::start().await;
        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let err = import_bundle(&client, &bundle).await.unwrap_err();
        assert!(err.to_string().contains("rp-ghost-99"));
    }

    #[tokio::test]
    async fn import_response_policy_errors_on_unmapped_notification() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = make_bundle(&tmp);
        std::fs::write(
            bundle.join("policies/response.json"),
            serde_json::to_string(&json!([{
                "id": "resp-src-1", "name": "Alert Policy", "enabled": false,
                "notificationSettingsIds": ["notif-unknown-99"]
            }])).unwrap(),
        ).unwrap();

        let server = MockServer::start().await;
        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let err = import_bundle(&client, &bundle).await.unwrap_err();
        assert!(err.to_string().contains("notif-unknown-99"));
    }

    #[tokio::test]
    async fn import_network_reputation_uploads_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = make_bundle(&tmp);
        let binary = b"\x00\x01\x02\xde\xad\xbe\xef";
        std::fs::write(bundle.join("policies/network-reputation.bin"), binary).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/policies/custom-reputation/import"))
            .and(header("content-type", "application/octet-stream"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        import_bundle(&client, &bundle).await.unwrap();
    }

    #[tokio::test]
    async fn import_strips_metadata_fields_before_post() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = make_bundle(&tmp);
        std::fs::write(
            bundle.join("integrations/image-registries.json"),
            serde_json::to_string(&json!([{
                "id": "reg-src-1", "name": "My Registry",
                "createdAt": "2024-01-01T00:00:00Z",
                "updatedAt": "2024-01-02T00:00:00Z",
                "lastChecked": "2024-01-03T00:00:00Z",
                "status": "active", "message": null,
                "apiUrl": "https://registry.example.com"
            }])).unwrap(),
        ).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "reg-tgt-1"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let mapper = import_bundle(&client, &bundle).await.unwrap();
        assert_eq!(mapper.resolve("image-registry", "reg-src-1").unwrap(), "reg-tgt-1");
    }
}
