use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

#[derive(Clone)]
pub struct KcsClient {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl KcsClient {
    pub fn new(base_url: &str, token: &str, verify_tls: bool, host_header: Option<&str>) -> Result<Self> {
        let mut default_headers = HeaderMap::new();
        default_headers.insert("Tron-Token", HeaderValue::from_str(token)?);
        if let Some(host) = host_header {
            default_headers.insert("Host", HeaderValue::from_str(host)?);
        }

        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(!verify_tls)
            .default_headers(default_headers)
            .build()?;

        Ok(Self {
            base: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http,
        })
    }

    pub async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(format!("{}{}", self.base, path))
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!("{}{}", self.base, path))
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.bytes().await?.to_vec())
    }

    pub async fn post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let resp = self
            .http
            .post(format!("{}{}", self.base, path))
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    pub async fn put_json(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let resp = self
            .http
            .put(format!("{}{}", self.base, path))
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        let bytes = resp.bytes().await?;
        if bytes.is_empty() {
            Ok(serde_json::Value::Object(Default::default()))
        } else {
            Ok(serde_json::from_slice(&bytes)?)
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    pub async fn put_bytes(&self, path: &str, data: Vec<u8>) -> Result<()> {
        self.http
            .put(format!("{}{}", self.base, path))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(data)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn client_injects_auth_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/healthz"))
            .and(header("Tron-Token", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "test-token", true, None).unwrap();
        let resp = client.get("/v1/healthz").await.unwrap();
        assert_eq!(resp["status"], "ok");
    }

    #[tokio::test]
    async fn client_post_sends_json_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/scanner"))
            .and(header("Tron-Token", "tok"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "new-id"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let resp = client.post("/v1/policies/scanner", &json!({"name": "test-pol"})).await.unwrap();
        assert_eq!(resp["id"], "new-id");
    }

    #[tokio::test]
    async fn client_put_json_returns_parsed_body() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/integrations/ldap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "ldap-1"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let resp = client.put_json("/v1/integrations/ldap", &json!({"name": "corp"})).await.unwrap();
        assert_eq!(resp["id"], "ldap-1");
    }

    #[tokio::test]
    async fn client_put_bytes_sends_octet_stream() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/policies/custom-reputation/import"))
            .and(header("content-type", "application/octet-stream"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        client.put_bytes("/v1/policies/custom-reputation/import", b"raw-data".to_vec()).await.unwrap();
    }

    #[tokio::test]
    async fn client_get_bytes_returns_raw_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/policies/custom-reputation/export"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"raw-export-data".to_vec()))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None).unwrap();
        let data = client.get_bytes("/v1/policies/custom-reputation/export").await.unwrap();
        assert_eq!(&data[..], b"raw-export-data");
    }
}
