//! # Overview
//!
//! Thin async wrapper around [`reqwest::Client`] that knows how to talk
//! to a KCS API endpoint: it injects the `Tron-Token` auth header on
//! every request, optionally overrides the `Host` header (useful when
//! the API is fronted by an ingress that routes by hostname), and can
//! be configured to skip TLS verification for self-signed targets.
//!
//! All higher-level modules ([`crate::export`], [`crate::importer`])
//! talk to KCS exclusively through [`KcsClient`].

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

/// # Overview
///
/// Authenticated HTTP client for a single KCS instance.
///
/// Cheap to `Clone` — internally wraps an [`reqwest::Client`], which
/// is itself an `Arc` over a connection pool. Cloning the `KcsClient`
/// lets multiple tasks share that pool.
#[derive(Clone)]
pub struct KcsClient {
    base: String,
    http: reqwest::Client,
}

impl KcsClient {
    /// # Overview
    ///
    /// Builds a client that targets `base_url` and presents `token`
    /// in the `Tron-Token` header on every request. Pass
    /// `verify_tls = false` to accept self-signed certificates; pass
    /// `host_header = Some("kcs.internal")` to override the `Host`
    /// header when the API is fronted by an ingress.
    ///
    /// The trailing slash (if any) on `base_url` is stripped so callers
    /// can pass paths starting with `/v1/...` without producing
    /// `//v1/...` URLs.
    ///
    /// # Errors
    ///
    /// Returns an error if `token` or `host_header` contain bytes that
    /// are not valid in an HTTP header, or if [`reqwest::Client`] fails
    /// to build (e.g. an invalid TLS configuration on the host).
    pub fn new(
        base_url: &str,
        token: &str,
        verify_tls: bool,
        host_header: Option<&str>,
    ) -> Result<Self> {
        let mut default_headers = HeaderMap::new();
        default_headers.insert("Tron-Token", HeaderValue::from_str(token)?);
        if let Some(host) = host_header {
            default_headers.insert("Host", HeaderValue::from_str(host)?);
        }

        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(!verify_tls)
            .default_headers(default_headers)
            .build()
            .with_context(|| format!("failed to build HTTP client for {base_url}"))?;

        Ok(Self {
            base: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// # Overview
    ///
    /// Sends `GET base_url + path` and parses the response body as JSON.
    /// `path` should start with `/` (e.g. `"/v1/policies/scanner"`).
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error if the request fails, an
    /// HTTP status error for any non-2xx response (via
    /// [`reqwest::Response::error_for_status`]), or a deserialization
    /// error if the body is not valid JSON.
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

    /// # Overview
    ///
    /// Sends `GET base_url + path` and returns the raw response body.
    /// Used for the network-reputation binary export, which is opaque
    /// blob data rather than JSON.
    ///
    /// # Errors
    ///
    /// Returns the transport error, or an HTTP status error for any
    /// non-2xx response.
    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!("{}{}", self.base, path))
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.bytes().await?.to_vec())
    }

    /// # Overview
    ///
    /// Sends `POST base_url + path` with `body` serialized as JSON and
    /// parses the response body as JSON.
    ///
    /// # Errors
    ///
    /// Returns the transport error, an HTTP status error for any
    /// non-2xx response, or a deserialization error if the body is not
    /// valid JSON. Callers in [`crate::importer`] match on the HTTP
    /// status (via [`anyhow::Error::downcast_ref`] to a
    /// [`reqwest::Error`]) to distinguish 400-graceful-skip from a hard
    /// failure.
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

    /// # Overview
    ///
    /// Sends `PUT base_url + path` with `body` serialized as JSON.
    /// Returns the parsed response body, or an empty JSON object when
    /// the server replies 2xx with no body (KCS does this for some
    /// idempotent update endpoints).
    ///
    /// # Errors
    ///
    /// Returns the transport error, an HTTP status error for any
    /// non-2xx response, or a deserialization error if the body is
    /// non-empty but not valid JSON.
    pub async fn put_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
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

    /// # Overview
    ///
    /// Returns the base URL the client was constructed with, with any
    /// trailing slash stripped. Used by [`crate::export::export_all`]
    /// to record the source URL in the bundle manifest.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// # Overview
    ///
    /// Sends `PUT base_url + path` with `data` as an
    /// `application/octet-stream` body. Used for the network-reputation
    /// binary upload during import.
    ///
    /// # Errors
    ///
    /// Returns the transport error, or an HTTP status error for any
    /// non-2xx response.
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
    async fn client_injects_auth_header() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/healthz"))
            .and(header("Tron-Token", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "test-token", true, None)?;
        let resp = client.get("/v1/healthz").await?;
        assert_eq!(resp["status"], "ok");
        Ok(())
    }

    #[tokio::test]
    async fn client_post_sends_json_body() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/scanner"))
            .and(header("Tron-Token", "tok"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "new-id"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let resp = client
            .post("/v1/policies/scanner", &json!({"name": "test-pol"}))
            .await?;
        assert_eq!(resp["id"], "new-id");
        Ok(())
    }

    #[tokio::test]
    async fn client_put_json_returns_parsed_body() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/integrations/ldap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "ldap-1"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let resp = client
            .put_json("/v1/integrations/ldap", &json!({"name": "corp"}))
            .await?;
        assert_eq!(resp["id"], "ldap-1");
        Ok(())
    }

    #[tokio::test]
    async fn client_put_bytes_sends_octet_stream() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/policies/custom-reputation/import"))
            .and(header("content-type", "application/octet-stream"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        client
            .put_bytes(
                "/v1/policies/custom-reputation/import",
                b"raw-data".to_vec(),
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn client_get_bytes_returns_raw_bytes() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/policies/custom-reputation/export"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"raw-export-data".to_vec()))
            .mount(&server)
            .await;

        let client = KcsClient::new(&server.uri(), "tok", true, None)?;
        let data = client
            .get_bytes("/v1/policies/custom-reputation/export")
            .await?;
        assert_eq!(&data[..], b"raw-export-data");
        Ok(())
    }
}
