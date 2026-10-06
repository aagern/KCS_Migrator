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
//!
//! # API generation
//!
//! A [`KcsClient`] is pinned to one [`ApiVersion`] and inserts that
//! version's path prefix itself. Callers pass **version-relative**
//! paths — `"/policies/scanner"`, not `"/v3/policies/scanner"` — so the
//! generation lives in exactly one place. [`KcsClient::detect`] probes
//! the instance and picks the generation from its release.
//!
//! # Cancel safety
//!
//! Every request method here is cancel-safe with respect to this
//! process: dropping the returned future at an `.await` aborts the
//! in-flight request and returns the connection to the pool, and
//! `KcsClient` holds no `&mut` state that could be left half-updated.
//!
//! The write methods carry a caveat that cancel safety does not cover:
//! a dropped [`KcsClient::post`], [`KcsClient::put_json`] or
//! [`KcsClient::put_bytes`] may already have been received and applied
//! by KCS. They are cancel-safe but **not idempotent**, so a cancelled
//! import must not be retried by re-running it against the same target.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

use crate::version::{self, ApiVersion, KcsVersion, VersionError};

/// # Overview
///
/// Request deadlines for a [`KcsClient`].
///
/// A named struct rather than two `Duration` arguments: both fields have
/// the same type, so a transposed call site is exactly the mistake the
/// compiler cannot catch for us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Bounds the TCP connect plus TLS handshake.
    pub connect: Duration,
    /// Bounds the whole round trip, including downloading the body.
    pub request: Duration,
}

impl Default for Timeouts {
    /// Deliberately generous on `request`: the network-reputation export
    /// returns a blob of unbounded size, and a per-item detail sweep over
    /// a large registry is slow. Operators can lower it.
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            request: Duration::from_secs(120),
        }
    }
}

/// # Overview
///
/// The HTTP status behind an [`anyhow::Error`] produced by this module,
/// or `None` if the failure was not an HTTP status error.
///
/// Every caller that needs to branch on a status — the graceful-skip
/// paths in [`crate::importer`], the "feature not configured" paths in
/// [`crate::export`] — goes through this rather than repeating the
/// downcast. Repeating it is how one site ends up checking `400` while
/// its neighbour checks `400 || 404` for the same condition.
#[must_use]
pub fn error_status(e: &anyhow::Error) -> Option<reqwest::StatusCode> {
    e.downcast_ref::<reqwest::Error>()
        .and_then(reqwest::Error::status)
}

/// # Overview
///
/// Whether an error is an HTTP 4xx.
///
/// Used where a 4xx means "this feature was never configured on the
/// source" rather than a failure worth aborting for.
#[must_use]
pub fn is_client_error(e: &anyhow::Error) -> bool {
    error_status(e).is_some_and(|s| s.is_client_error())
}

/// What a single `healthz` probe told us.
///
/// Distinguishing these is what lets [`KcsClient::detect`] give a useful
/// diagnosis: a missing route means "try the other generation", while a
/// rejected token means "stop, the credential is wrong" — retrying the
/// second generation with the same token would only waste a round trip
/// and then report the wrong problem.
enum Probe {
    /// The instance reported its release.
    Version(KcsVersion),
    /// 404 — this generation is not served here.
    Missing,
    /// 401/403 — the route exists but the token was rejected.
    Unauthorized(u16),
    /// Anything else: transport failure, 5xx, or an unparseable body.
    Failed(anyhow::Error),
}

/// # Overview
///
/// Authenticated HTTP client for a single KCS instance, pinned to one
/// API generation.
///
/// Cheap to `Clone` — internally wraps an [`reqwest::Client`], which
/// is itself an `Arc` over a connection pool. Cloning the `KcsClient`
/// lets multiple tasks share that pool.
#[derive(Clone)]
pub struct KcsClient {
    base: String,
    api: ApiVersion,
    http: reqwest::Client,
    /// When set, writes are described on stdout and never sent.
    dry_run: bool,
    /// Supplies the synthetic IDs a dry run hands back in place of the
    /// server's. `Arc<AtomicU64>` rather than a plain counter because
    /// `KcsClient` is shared behind `&self` and cloned to share the
    /// connection pool, so the sequence has to be shared too -- a
    /// per-clone counter would mint colliding IDs.
    dry_run_seq: Arc<AtomicU64>,
}

/// Builds the underlying HTTP client: auth header, optional `Host`
/// override, TLS policy and timeouts.
///
/// # Errors
///
/// Returns an error if `token` or `host_header` contain bytes that are
/// not valid in an HTTP header, or if [`reqwest::Client`] fails to build.
fn build_http(
    base_url: &str,
    token: &str,
    verify_tls: bool,
    host_header: Option<&str>,
    timeouts: Timeouts,
) -> Result<reqwest::Client> {
    let mut default_headers = HeaderMap::new();
    default_headers.insert("Tron-Token", HeaderValue::from_str(token)?);
    if let Some(host) = host_header {
        default_headers.insert("Host", HeaderValue::from_str(host)?);
    }

    reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .default_headers(default_headers)
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.request)
        .build()
        .with_context(|| format!("failed to build HTTP client for {base_url}"))
}

/// Sends one `GET {base}{prefix}/healthz` and classifies the result.
///
/// # Cancel safety
///
/// Cancel-safe. One read-only GET, no local state, nothing written.
async fn probe_healthz(http: &reqwest::Client, base: &str, prefix: &str) -> Probe {
    let resp = match http.get(format!("{base}{prefix}/healthz")).send().await {
        Ok(r) => r,
        Err(e) => return Probe::Failed(e.into()),
    };

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Probe::Missing;
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Probe::Unauthorized(status.as_u16());
    }
    if !status.is_success() {
        return Probe::Failed(anyhow!(
            "GET {prefix}/healthz returned HTTP {}",
            status.as_u16()
        ));
    }

    match resp.json::<serde_json::Value>().await {
        Ok(body) => match version::from_healthz_body(&body) {
            Ok(v) => Probe::Version(v),
            Err(e) => Probe::Failed(e.into()),
        },
        Err(e) => Probe::Failed(e.into()),
    }
}

/// Hand-written rather than derived: `KcsClient` holds the API token inside the
/// wrapped [`reqwest::Client`]'s default headers, and a derived `Debug` would print
/// whatever that type chooses to expose. Only the two fields that are safe to log
/// appear here, so the token cannot reach a log line, a panic message or a test
/// failure by accident.
impl std::fmt::Debug for KcsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcsClient")
            .field("base", &self.base)
            .field("api", &self.api)
            .field("token", &"<redacted>")
            .field("dry_run", &self.dry_run)
            .finish_non_exhaustive()
    }
}

impl KcsClient {
    /// # Overview
    ///
    /// Builds a client that targets `base_url`, speaks the `api`
    /// generation, and presents `token` in the `Tron-Token` header on
    /// every request. Pass `verify_tls = false` to accept self-signed
    /// certificates; pass `host_header = Some("kcs.internal")` to
    /// override the `Host` header when the API is fronted by an ingress.
    ///
    /// The trailing slash (if any) on `base_url` is stripped, and the
    /// version prefix is inserted by the client, so callers pass
    /// version-relative paths like `"/policies/scanner"`.
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
        api: ApiVersion,
        timeouts: Timeouts,
    ) -> Result<Self> {
        let http = build_http(base_url, token, verify_tls, host_header, timeouts)?;
        Ok(Self {
            base: base_url.trim_end_matches('/').to_string(),
            api,
            http,
            dry_run: false,
            dry_run_seq: Arc::new(AtomicU64::new(0)),
        })
    }

    /// # Overview
    ///
    /// Probes `base_url` for its KCS release and returns a client pinned
    /// to the matching API generation, together with the release found.
    ///
    /// Tries `GET /v1/healthz` first, since every release serves it, and
    /// falls through to `GET /v3/healthz` for a release that has dropped
    /// `v1` (expected from KCS 2.6). A rejected token stops the probe
    /// immediately rather than repeating it against the second
    /// generation.
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe. Two sequential read-only GETs; a drop leaves nothing
    /// behind on either side.
    ///
    /// # Errors
    ///
    /// Returns an authentication error if the instance rejected the
    /// token, the underlying transport error if the instance could not be
    /// reached, or [`VersionError::Undetectable`] — whose message names
    /// the `--api-version` override — if no generation reported a
    /// version.
    pub async fn detect(
        base_url: &str,
        token: &str,
        verify_tls: bool,
        host_header: Option<&str>,
        timeouts: Timeouts,
    ) -> Result<(Self, KcsVersion)> {
        let http = build_http(base_url, token, verify_tls, host_header, timeouts)?;
        let base = base_url.trim_end_matches('/').to_string();

        for prefix in [ApiVersion::V1.prefix(), ApiVersion::V3.prefix()] {
            match probe_healthz(&http, &base, prefix).await {
                Probe::Version(found) => {
                    let api = ApiVersion::for_kcs(found);
                    return Ok((
                        Self {
                            base,
                            api,
                            http,
                            dry_run: false,
                            dry_run_seq: Arc::new(AtomicU64::new(0)),
                        },
                        found,
                    ));
                }
                // This generation is not served here; fall out of the match and let
                // the loop try the next prefix. (An explicit `continue` here is what
                // `clippy::needless_continue` objects to, since it is the last thing
                // the loop body would do anyway.)
                Probe::Missing => (),
                // The same token would be rejected by the next probe too.
                Probe::Unauthorized(code) => {
                    return Err(anyhow!(
                        "KCS at {base} rejected the API token (HTTP {code}). Check \
                         --token / KCS_TOKEN; the value is shown on the 'My profile' \
                         page of the KCS web console."
                    ))
                }
                // Transport or server failure — retrying the other generation
                // against the same host would report the wrong cause.
                Probe::Failed(e) => {
                    return Err(e.context(format!(
                        "failed to read the KCS version from {base}{prefix}/healthz"
                    )))
                }
            }
        }

        Err(VersionError::Undetectable.into())
    }

    /// # Overview
    ///
    /// Returns this client with writes disabled.
    ///
    /// In dry-run mode [`Self::post`], [`Self::put_json`] and
    /// [`Self::put_bytes`] describe what they would send on stdout and
    /// return a synthetic response instead of sending anything. Reads
    /// still go to the server, so the whole pipeline — including
    /// foreign-key rewriting, which needs a created resource's ID — runs
    /// end to end against real data.
    ///
    /// A builder method rather than another [`Self::new`] parameter: that
    /// signature already takes six arguments, and dry-run is orthogonal
    /// to how the connection is made.
    #[must_use]
    pub const fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// # Overview
    ///
    /// Whether writes are suppressed.
    #[must_use]
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Reports a suppressed write and mints the synthetic ID that stands in
    /// for the one the server would have assigned.
    fn describe_suppressed_write(&self, verb: &str, path: &str, body_len: usize) -> String {
        let seq = self.dry_run_seq.fetch_add(1, Ordering::Relaxed);
        let id = format!("dry-run-{seq:04}");
        println!(
            "DRY RUN  {verb:4} {}  ({body_len} bytes)  -> id {id}",
            self.url(path)
        );
        id
    }

    /// # Overview
    ///
    /// Which API generation this client speaks.
    #[must_use]
    pub const fn api_version(&self) -> ApiVersion {
        self.api
    }

    /// Builds an absolute URL from a version-relative path:
    /// `"/policies/scanner"` → `"{base}/v3/policies/scanner"`.
    fn url(&self, rel: &str) -> String {
        format!("{}{}{}", self.base, self.api.prefix(), rel)
    }

    /// # Overview
    ///
    /// Sends `GET` to the version-relative `path` and parses the
    /// response body as JSON. `path` should start with `/` and omit the
    /// version segment (e.g. `"/policies/scanner"`).
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe. Read-only, no local state across the `.await`.
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
            .get(self.url(path))
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// # Overview
    ///
    /// Sends `GET` to the version-relative `path` and returns the raw
    /// response body. Used for the network-reputation binary export,
    /// which is opaque blob data rather than JSON.
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe. Read-only; a drop discards a partially-downloaded
    /// body without surfacing it.
    ///
    /// # Errors
    ///
    /// Returns the transport error, or an HTTP status error for any
    /// non-2xx response.
    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(self.url(path))
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.bytes().await?.to_vec())
    }

    /// # Overview
    ///
    /// Sends `POST` to the version-relative `path` with `body`
    /// serialized as JSON and parses the response body as JSON.
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe for this process, but **not idempotent**: a dropped
    /// future may already have been applied by the server. See the
    /// module docs.
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
        if self.dry_run {
            let len = serde_json::to_vec(body).map_or(0, |v| v.len());
            let id = self.describe_suppressed_write("POST", path, len);
            return Ok(serde_json::json!({ "id": id }));
        }
        let resp = self
            .http
            .post(self.url(path))
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// # Overview
    ///
    /// Sends `PUT` to the version-relative `path` with `body` serialized
    /// as JSON. Returns the parsed response body, or an empty JSON
    /// object when the server replies 2xx with no body (KCS does this
    /// for some idempotent update endpoints).
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe for this process, but **not idempotent**. See the
    /// module docs.
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
        if self.dry_run {
            let len = serde_json::to_vec(body).map_or(0, |v| v.len());
            self.describe_suppressed_write("PUT", path, len);
            return Ok(serde_json::Value::Object(serde_json::Map::default()));
        }
        let resp = self
            .http
            .put(self.url(path))
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        let bytes = resp.bytes().await?;
        if bytes.is_empty() {
            Ok(serde_json::Value::Object(serde_json::Map::default()))
        } else {
            Ok(serde_json::from_slice(&bytes)?)
        }
    }

    /// # Overview
    ///
    /// Returns the base URL the client was constructed with, with any
    /// trailing slash stripped and without the version segment. Used by
    /// [`crate::export::export_all`] to record the source URL in the
    /// bundle manifest.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// # Overview
    ///
    /// Sends `PUT` to the version-relative `path` with `data` as an
    /// `application/octet-stream` body. Used for the network-reputation
    /// binary upload during import.
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe for this process, but **not idempotent**. See the
    /// module docs.
    ///
    /// # Errors
    ///
    /// Returns the transport error, or an HTTP status error for any
    /// non-2xx response.
    pub async fn put_bytes(&self, path: &str, data: Vec<u8>) -> Result<()> {
        if self.dry_run {
            self.describe_suppressed_write("PUT", path, data.len());
            return Ok(());
        }
        self.http
            .put(self.url(path))
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
    use serde_json::{json, Value};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A V1 client with default timeouts, for the transport tests.
    fn v1_client(uri: &str, token: &str) -> Result<KcsClient> {
        KcsClient::new(uri, token, true, None, ApiVersion::V1, Timeouts::default())
    }

    #[tokio::test]
    async fn client_injects_auth_header() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/healthz"))
            .and(header("Tron-Token", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
            .mount(&server)
            .await;

        let client = v1_client(&server.uri(), "test-token")?;
        let resp = client.get("/healthz").await?;
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

        let client = v1_client(&server.uri(), "tok")?;
        let resp = client
            .post("/policies/scanner", &json!({"name": "test-pol"}))
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

        let client = v1_client(&server.uri(), "tok")?;
        let resp = client
            .put_json("/integrations/ldap", &json!({"name": "corp"}))
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

        let client = v1_client(&server.uri(), "tok")?;
        client
            .put_bytes("/policies/custom-reputation/import", b"raw-data".to_vec())
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

        let client = v1_client(&server.uri(), "tok")?;
        let data = client
            .get_bytes("/policies/custom-reputation/export")
            .await?;
        assert_eq!(&data[..], b"raw-export-data");
        Ok(())
    }

    // ---- §7.3 path prefixing ----

    #[tokio::test]
    async fn v3_client_prefixes_paths_with_v3() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/policies/scanner"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
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
        // The same relative path the V1 test uses — only the client differs.
        client.get("/policies/scanner").await?;
        assert_eq!(client.api_version(), ApiVersion::V3);
        Ok(())
    }

    #[tokio::test]
    async fn v1_client_prefixes_paths_with_v1() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/policies/scanner"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;

        let client = v1_client(&server.uri(), "tok")?;
        client.get("/policies/scanner").await?;
        assert_eq!(client.api_version(), ApiVersion::V1);
        Ok(())
    }

    #[test]
    fn base_url_keeps_no_version_segment_and_no_trailing_slash() -> Result<()> {
        let client = KcsClient::new(
            "https://kcs.demo.lab/api/",
            "tok",
            true,
            None,
            ApiVersion::V3,
            Timeouts::default(),
        )?;
        assert_eq!(client.base_url(), "https://kcs.demo.lab/api");
        assert_eq!(
            client.url("/policies/scanner"),
            "https://kcs.demo.lab/api/v3/policies/scanner"
        );
        Ok(())
    }

    // ---- §7.2 version detection over the wire ----

    /// Mounts `GET {prefix}/healthz` with a given status and optional body.
    async fn mount_healthz(server: &MockServer, prefix: &str, status: u16, body: Option<Value>) {
        let template = body.map_or_else(
            || ResponseTemplate::new(status),
            |b| ResponseTemplate::new(status).set_body_json(b),
        );
        Mock::given(method("GET"))
            .and(path(format!("{prefix}/healthz")))
            .respond_with(template)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn detect_picks_v3_for_a_2_5_instance() -> Result<()> {
        let server = MockServer::start().await;
        mount_healthz(&server, "/v1", 200, Some(json!({"version": "2.5.0"}))).await;

        let (client, found) =
            KcsClient::detect(&server.uri(), "tok", true, None, Timeouts::default()).await?;
        assert_eq!(found, KcsVersion::new(2, 5, 0));
        assert_eq!(client.api_version(), ApiVersion::V3);
        Ok(())
    }

    #[tokio::test]
    async fn detect_picks_v1_for_a_2_4_instance() -> Result<()> {
        let server = MockServer::start().await;
        mount_healthz(&server, "/v1", 200, Some(json!({"version": "2.4.1"}))).await;

        let (client, found) =
            KcsClient::detect(&server.uri(), "tok", true, None, Timeouts::default()).await?;
        assert_eq!(found, KcsVersion::new(2, 4, 1));
        assert_eq!(client.api_version(), ApiVersion::V1);
        Ok(())
    }

    #[tokio::test]
    async fn detect_falls_through_to_v3_when_v1_is_gone() -> Result<()> {
        // The shape expected from KCS 2.6, which deprecates v1.
        let server = MockServer::start().await;
        mount_healthz(&server, "/v1", 404, None).await;
        mount_healthz(&server, "/v3", 200, Some(json!({"version": "2.6.0"}))).await;

        let (client, found) =
            KcsClient::detect(&server.uri(), "tok", true, None, Timeouts::default()).await?;
        assert_eq!(found, KcsVersion::new(2, 6, 0));
        assert_eq!(client.api_version(), ApiVersion::V3);
        Ok(())
    }

    #[tokio::test]
    async fn detect_reports_undetectable_naming_the_override_flag() {
        let server = MockServer::start().await;
        mount_healthz(&server, "/v1", 404, None).await;
        mount_healthz(&server, "/v3", 404, None).await;

        let err = KcsClient::detect(&server.uri(), "tok", true, None, Timeouts::default())
            .await
            .expect_err("both probes 404, detection must fail");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("--api-version"),
            "operator needs the override flag named, got: {rendered}"
        );
    }

    #[tokio::test]
    async fn detect_stops_on_a_rejected_token_without_probing_v3() -> Result<()> {
        // Only /v1/healthz is mounted. If detect were to fall through to /v3 on a
        // 403, wiremock would record an unmatched request — and the diagnosis the
        // operator sees would be "undetectable version" instead of "bad token".
        let server = MockServer::start().await;
        mount_healthz(
            &server,
            "/v1",
            403,
            Some(json!({"code": "MDD-001", "message": "login failed"})),
        )
        .await;

        let err = KcsClient::detect(&server.uri(), "tok", true, None, Timeouts::default())
            .await
            .expect_err("a rejected token must fail detection");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("token"),
            "error should point at the token, got: {rendered}"
        );

        let healthz_requests = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path().ends_with("/healthz"))
            .count();
        assert_eq!(healthz_requests, 1, "must not retry v3 with the same token");
        Ok(())
    }

    // ---- §7.4 timeouts ----

    #[test]
    fn default_timeouts_are_10s_connect_120s_request() {
        let t = Timeouts::default();
        assert_eq!(t.connect, Duration::from_secs(10));
        assert_eq!(t.request, Duration::from_secs(120));
    }

    #[tokio::test]
    async fn request_timeout_fires_on_a_server_that_never_responds() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/policies/scanner"))
            // Far longer than the client's budget, so the deadline is what ends the call.
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items": []}))
                    .set_delay(Duration::from_secs(30)),
            )
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            None,
            ApiVersion::V1,
            Timeouts {
                connect: Duration::from_millis(500),
                request: Duration::from_millis(150),
            },
        )?;

        let err = client
            .get("/policies/scanner")
            .await
            .expect_err("a 30s response against a 150ms budget must time out");
        let as_reqwest = err
            .downcast_ref::<reqwest::Error>()
            .ok_or_else(|| anyhow!("expected a reqwest error, got: {err}"))?;
        assert!(
            as_reqwest.is_timeout(),
            "expected a timeout, got: {as_reqwest}"
        );
        Ok(())
    }

    // ---- host header override ----

    #[tokio::test]
    async fn host_header_override_actually_reaches_the_server() -> Result<()> {
        // The README documents --host-header for reaching KCS by ingress IP, and
        // it is implemented by putting Host into reqwest's default_headers. Whether
        // hyper overwrites that from the URL authority was never verified, so the
        // feature was documented but unproven. This pins it.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/healthz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
            .mount(&server)
            .await;

        let client = KcsClient::new(
            &server.uri(),
            "tok",
            true,
            Some("kcs.demo.lab"),
            ApiVersion::V1,
            Timeouts::default(),
        )?;
        client.get("/healthz").await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let host = seen
            .first()
            .and_then(|r| r.headers.get("host"))
            .map(|v| String::from_utf8_lossy(v.as_bytes()).to_string());
        assert_eq!(
            host.as_deref(),
            Some("kcs.demo.lab"),
            "the Host override must survive to the wire, not be replaced by the URL \
             authority; got {host:?}"
        );
        Ok(())
    }

    // ---- §7.6 dry run ----

    #[tokio::test]
    async fn dry_run_suppresses_writes_but_still_reads() -> Result<()> {
        let server = MockServer::start().await;
        // Reads succeed. Writes are mounted to fail loudly: if dry-run let one
        // through, the 500 would surface as an error instead of a silent pass.
        Mock::given(method("GET"))
            .and(path("/v1/policies/scanner"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = v1_client(&server.uri(), "tok")?.with_dry_run(true);
        assert!(client.is_dry_run());

        client.get("/policies/scanner").await?;
        client
            .post("/policies/scanner", &json!({"name": "p"}))
            .await?;
        client
            .put_json("/integrations/ldap", &json!({"n": 1}))
            .await?;
        client
            .put_bytes("/policies/custom-reputation/import", b"blob".to_vec())
            .await?;

        let seen = server.received_requests().await.unwrap_or_default();
        let non_get: Vec<_> = seen
            .iter()
            .filter(|r| r.method != wiremock::http::Method::GET)
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect();
        assert!(
            non_get.is_empty(),
            "dry run must send no writes, sent: {non_get:?}"
        );
        assert_eq!(seen.len(), 1, "the read should still have gone out");
        Ok(())
    }

    #[tokio::test]
    async fn dry_run_mints_distinct_ids_so_fk_rewriting_still_works() -> Result<()> {
        // The importer registers a created resource's id and rewrites later
        // references to it. A dry run that returned the same id twice, or none,
        // would collapse those mappings and hide real FK bugs.
        let server = MockServer::start().await;
        let client = v1_client(&server.uri(), "tok")?.with_dry_run(true);

        let first = client.post("/policies/runtime-profile", &json!({})).await?;
        let second = client.post("/policies/runtime-profile", &json!({})).await?;

        let id_of = |v: &Value| v["id"].as_str().unwrap_or_default().to_string();
        assert!(!id_of(&first).is_empty());
        assert_ne!(id_of(&first), id_of(&second));
        Ok(())
    }

    #[tokio::test]
    async fn dry_run_sequence_is_shared_across_clones() -> Result<()> {
        // KcsClient is cloned to share the connection pool. A per-clone counter
        // would mint colliding synthetic ids across those clones.
        let server = MockServer::start().await;
        let client = v1_client(&server.uri(), "tok")?.with_dry_run(true);
        let clone = client.clone();

        let a = client.post("/policies/scanner", &json!({})).await?;
        let b = clone.post("/policies/scanner", &json!({})).await?;
        assert_ne!(a["id"], b["id"]);
        Ok(())
    }

    #[tokio::test]
    async fn writes_are_sent_when_dry_run_is_off() -> Result<()> {
        // The twin of the suppression test: proves with_dry_run(false) is not
        // silently suppressing everything.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/policies/scanner"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "real"})))
            .mount(&server)
            .await;

        let client = v1_client(&server.uri(), "tok")?.with_dry_run(false);
        let out = client.post("/policies/scanner", &json!({})).await?;
        assert_eq!(out["id"], "real");
        assert_eq!(
            server.received_requests().await.unwrap_or_default().len(),
            1
        );
        Ok(())
    }

    // ---- §7.3 the version lives in one place ----

    /// Returns the portion of a module's source before its `#[cfg(test)]` block.
    ///
    /// Test code legitimately names `/v1/...` and `/v3/...` in wiremock matchers —
    /// those are the URLs we assert the client builds. Only shipped code has to be
    /// free of them.
    fn production_source(src: &str) -> &str {
        src.split("#[cfg(test)]").next().unwrap_or(src)
    }

    #[test]
    fn no_versioned_path_literals_remain_in_shipped_code() {
        for (name, src) in [
            ("export.rs", include_str!("export.rs")),
            ("importer.rs", include_str!("importer.rs")),
        ] {
            let prod = production_source(src);
            for needle in ["\"/v1/", "\"/v3/"] {
                assert!(
                    !prod.contains(needle),
                    "{name} still contains the literal {needle}… — the API generation \
                     belongs to KcsClient, not to call sites"
                );
            }
        }
    }
}
