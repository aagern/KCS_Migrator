use crate::client::KcsClient;
use anyhow::Result;
use chrono::Utc;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

fn write_json(path: &Path, data: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(data)?)?;
    Ok(())
}

async fn get_list(client: &KcsClient, api_path: &str) -> Result<Value> {
    match client.get(api_path).await {
        Ok(data) => {
            if data.is_array() {
                Ok(data)
            } else if let Some(items) = data.get("items") {
                Ok(items.clone())
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

pub async fn export_all(client: &KcsClient, output_dir: &Path) -> Result<PathBuf> {
    let ts = Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let bundle = output_dir.join(format!("kcs-export-{ts}"));

    // Integrations
    let registries = get_list(client, "/v1/integrations/image-registries").await?;
    write_json(&bundle.join("integrations/image-registries.json"), &registries)?;

    let ldap = get_list(client, "/v1/integrations/ldap").await?;
    write_json(&bundle.join("integrations/ldap.json"), &ldap)?;

    let sso = get_single(client, "/v1/integrations/sso").await?;
    write_json(&bundle.join("integrations/sso.json"), &sso)?;

    let llm = get_single(client, "/v1/integrations/llm").await?;
    write_json(&bundle.join("integrations/llm.json"), &llm)?;

    let agent_groups = get_list(client, "/v1/integrations/agent-group").await?;
    write_json(&bundle.join("integrations/agent-groups.json"), &agent_groups)?;

    let sign_validators = get_list(client, "/v1/integrations/sign-validators").await?;
    write_json(
        &bundle.join("integrations/sign-validators-REFERENCE.json"),
        &sign_validators,
    )?;

    // Notification channels — reference only
    let notif_email = get_list(client, "/v1/integrations/notification-settings/email").await?;
    let notif_tg = get_list(client, "/v1/integrations/notification-settings/telegram").await?;
    let notif_wh = get_list(client, "/v1/integrations/notification-settings/webhook").await?;
    write_json(
        &bundle.join("integrations/notifications-REFERENCE.json"),
        &json!({"email": notif_email, "telegram": notif_tg, "webhook": notif_wh}),
    )?;

    // Policies
    let scanner_pols = get_list(client, "/v1/policies/scanner").await?;
    write_json(&bundle.join("policies/scanner.json"), &scanner_pols)?;

    let assurance_pols = get_list(client, "/v1/policies/assurance").await?;
    write_json(&bundle.join("policies/assurance.json"), &assurance_pols)?;

    let rt_profiles = get_list(client, "/v1/policies/runtime-profile").await?;
    write_json(&bundle.join("policies/runtime-profiles.json"), &rt_profiles)?;

    let rt_pols = get_list(client, "/v1/policies/runtime").await?;
    write_json(&bundle.join("policies/runtime.json"), &rt_pols)?;

    let resp_pols = get_list(client, "/v1/policies/response").await?;
    write_json(&bundle.join("policies/response.json"), &resp_pols)?;

    // Network reputation binary
    let net_rep = client
        .get_bytes("/v1/policies/custom-reputation/export")
        .await?;
    let rep_path = bundle.join("policies/network-reputation.bin");
    std::fs::create_dir_all(rep_path.parent().unwrap())?;
    std::fs::write(&rep_path, net_rep)?;

    // Components
    let scanner_prio = get_single(client, "/v1/scanners/priority").await?;
    write_json(&bundle.join("components/scanner-priority.json"), &scanner_prio)?;

    // Config
    let reports_cfg = get_single(client, "/v1/reports/storage/config").await?;
    write_json(&bundle.join("config/reports-storage.json"), &reports_cfg)?;

    // Manifest
    write_json(
        &bundle.join("manifest.json"),
        &json!({
            "tool_version": TOOL_VERSION,
            "timestamp": ts,
            "source_url": client.base_url(),
        }),
    )?;

    Ok(bundle)
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
    async fn export_writes_image_registries() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"id": "r1", "description": "hub", "apiUrl": "https://hub.docker.com"}]
            })))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir().unwrap();
        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let bundle = export_all(&client, tmp.path()).await.unwrap();

        let data: Value = serde_json::from_str(
            &std::fs::read_to_string(bundle.join("integrations/image-registries.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(data[0]["id"], "r1");
    }

    #[tokio::test]
    async fn export_creates_manifest_with_timestamp_and_version() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir().unwrap();
        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let bundle = export_all(&client, tmp.path()).await.unwrap();

        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(bundle.join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest.get("timestamp").is_some());
        assert_eq!(manifest["tool_version"], TOOL_VERSION);
    }

    #[tokio::test]
    async fn export_bundle_name_starts_with_kcs_export() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/integrations/image-registries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        stub_empty(&server).await;

        let tmp = tempfile::tempdir().unwrap();
        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let bundle = export_all(&client, tmp.path()).await.unwrap();

        assert!(bundle
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("kcs-export-"));
    }

    #[tokio::test]
    async fn export_writes_notifications_reference_with_all_keys() {
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

        let tmp = tempfile::tempdir().unwrap();
        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let bundle = export_all(&client, tmp.path()).await.unwrap();

        let notif: Value = serde_json::from_str(
            &std::fs::read_to_string(
                bundle.join("integrations/notifications-REFERENCE.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(notif.get("email").is_some());
        assert!(notif.get("telegram").is_some());
        assert!(notif.get("webhook").is_some());
    }

    #[tokio::test]
    async fn export_writes_network_reputation_binary() {
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

        let tmp = tempfile::tempdir().unwrap();
        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let bundle = export_all(&client, tmp.path()).await.unwrap();

        let bin = std::fs::read(bundle.join("policies/network-reputation.bin")).unwrap();
        assert_eq!(bin, b"binary-data");
    }
}
