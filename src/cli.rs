//! # Overview
//!
//! Connection options shared by every subcommand, and the rules for
//! turning them into a [`KcsClient`].
//!
//! This lives in the library rather than in `main.rs` so the decisions
//! it encodes are testable: which API generation gets used, where the
//! token comes from, and — the one that matters most — that passing
//! `--api-version` explicitly performs **no** detection request at all.
//! An override that still probes is an override that can still fail.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Args, ValueEnum};

use crate::client::{KcsClient, Timeouts};
use crate::version::{ApiVersion, KcsVersion};

/// # Overview
///
/// `--api-version` as the operator types it.
///
/// Separate from [`ApiVersion`] because this type has a third state the
/// domain type must not have: `auto`. Keeping "ask the server" out of
/// [`ApiVersion`] means no code downstream of the client can be handed a
/// generation that has not been decided yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum ApiVersionArg {
    /// Probe `GET /healthz` and pick from the reported release.
    #[default]
    Auto,
    /// Force `APIv1` (KCS 2.4 and earlier, or the 2.5 compatibility shim).
    V1,
    /// Force `APIv3` (KCS 2.5 and later).
    V3,
}

impl ApiVersionArg {
    /// The pinned generation, or `None` for `auto`.
    #[must_use]
    pub const fn pinned(self) -> Option<ApiVersion> {
        match self {
            Self::Auto => None,
            Self::V1 => Some(ApiVersion::V1),
            Self::V3 => Some(ApiVersion::V3),
        }
    }
}

/// # Overview
///
/// How a client reached a KCS instance: by probing, or because the
/// operator said so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// Detected from `GET /healthz`; carries the release found.
    Detected(KcsVersion),
    /// Pinned by `--api-version`; no release was requested.
    Pinned(ApiVersion),
}

impl Resolved {
    /// # Overview
    ///
    /// The release behind this connection, when one was detected.
    ///
    /// `None` for a pinned generation: `--api-version` deliberately sends
    /// no probe, so there is no release to report. The bundle manifest
    /// records `null` in that case rather than a guess.
    #[must_use]
    pub const fn kcs_version(&self) -> Option<KcsVersion> {
        match self {
            Self::Detected(v) => Some(*v),
            Self::Pinned(_) => None,
        }
    }

    /// # Overview
    ///
    /// The API generation in use, however it was arrived at.
    ///
    /// Not `const`: it defers to [`ApiVersion::for_kcs`], which compares
    /// through the derived `Ord` on [`KcsVersion`] and so cannot be
    /// const-evaluated. Hand-rolling the comparison here to win `const`
    /// would duplicate the version gate in a second place, which is the
    /// thing the ordering test exists to prevent.
    #[must_use]
    pub fn api_version(&self) -> ApiVersion {
        match self {
            Self::Detected(v) => ApiVersion::for_kcs(*v),
            Self::Pinned(api) => *api,
        }
    }
}

impl std::fmt::Display for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Detected(v) => write!(f, "KCS {v} (detected)"),
            Self::Pinned(api) => {
                write!(
                    f,
                    "API{} (pinned by --api-version)",
                    api.prefix().trim_start_matches('/')
                )
            }
        }
    }
}

/// # Overview
///
/// Connection options common to `export` and `import-bundle`.
#[derive(Debug, Args)]
pub struct ConnOpts {
    /// KCS base URL including the `/api` suffix, without a version segment.
    #[arg(long, env = "KCS_URL")]
    pub url: String,

    /// API token. Prefer `--token-file` or the `KCS_TOKEN` environment
    /// variable: a token passed as an argument is visible to every other
    /// process on the host via the process list, and lands in shell history.
    #[arg(long, env = "KCS_TOKEN", value_name = "TOKEN")]
    pub token: Option<String>,

    /// File whose first line is the API token. Takes precedence over
    /// `--token` and `KCS_TOKEN`.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,

    /// Skip TLS certificate verification (self-signed targets).
    #[arg(long)]
    pub no_verify_tls: bool,

    /// Override the HTTP `Host` header, for connecting by ingress IP.
    #[arg(long, value_name = "HOST")]
    pub host_header: Option<String>,

    /// Which KCS API generation to speak. `auto` probes `GET /healthz`.
    #[arg(long, value_enum, default_value_t = ApiVersionArg::Auto)]
    pub api_version: ApiVersionArg,

    /// Deadline for a whole request, including body download.
    #[arg(long, value_name = "SECONDS", default_value_t = 120)]
    pub timeout_secs: u64,

    /// Deadline for the TCP connect plus TLS handshake.
    #[arg(long, value_name = "SECONDS", default_value_t = 10)]
    pub connect_timeout_secs: u64,
}

/// Resolves the API token from `--token-file`, `--token` or `KCS_TOKEN`.
///
/// `--token-file` wins when both are present. The precedence is fixed
/// rather than an error because `KCS_TOKEN` is commonly exported for a
/// whole shell session, so treating "env set *and* file given" as a
/// conflict would reject a reasonable invocation.
///
/// # Errors
///
/// Returns an error naming all three sources when none supplied a value,
/// or if the file cannot be read or holds no non-empty first line.
fn resolve_token(token: Option<&str>, token_file: Option<&Path>) -> Result<String> {
    if let Some(path) = token_file {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read token file {}", path.display()))?;
        // First line only, trimmed: a token file written with `echo` ends in a
        // newline, and a newline inside an HTTP header value is a request
        // smuggling primitive, not a token.
        let first = text.lines().next().unwrap_or("").trim();
        if first.is_empty() {
            return Err(anyhow!(
                "token file {} has no token on its first line",
                path.display()
            ));
        }
        return Ok(first.to_string());
    }

    match token.map(str::trim) {
        Some(t) if !t.is_empty() => Ok(t.to_string()),
        _ => Err(anyhow!(
            "no API token supplied: pass --token-file <PATH> (preferred), --token <TOKEN>, \
             or set KCS_TOKEN. The value is on the 'My profile' page of the KCS web console."
        )),
    }
}

impl ConnOpts {
    /// The request deadlines these options describe.
    #[must_use]
    pub const fn timeouts(&self) -> Timeouts {
        Timeouts {
            connect: Duration::from_secs(self.connect_timeout_secs),
            request: Duration::from_secs(self.timeout_secs),
        }
    }

    /// # Overview
    ///
    /// Builds a client for the instance these options describe.
    ///
    /// With `--api-version auto` this probes `GET /healthz` and pins the
    /// client to the generation matching the reported release. With an
    /// explicit `v1` or `v3` it sends **nothing** — the override exists
    /// for instances where detection cannot work, so an override that
    /// still depended on a request would be useless in exactly the case
    /// it is meant for.
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe. Either no request at all, or the read-only probes in
    /// [`KcsClient::detect`].
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be resolved, if the HTTP
    /// client cannot be built, or — in `auto` mode — if detection fails.
    pub async fn connect(&self) -> Result<(KcsClient, Resolved)> {
        let token = resolve_token(self.token.as_deref(), self.token_file.as_deref())?;
        let verify_tls = !self.no_verify_tls;
        let timeouts = self.timeouts();

        // An explicit --api-version must send nothing at all: the override exists
        // for instances where detection cannot work, so one that still depended on
        // a request would be useless in exactly the case it is meant for.
        if let Some(api) = self.api_version.pinned() {
            let client = KcsClient::new(
                &self.url,
                &token,
                verify_tls,
                self.host_header.as_deref(),
                api,
                timeouts,
            )?;
            return Ok((client, Resolved::Pinned(api)));
        }

        let (client, found) = KcsClient::detect(
            &self.url,
            &token,
            verify_tls,
            self.host_header.as_deref(),
            timeouts,
        )
        .await?;
        Ok((client, Resolved::Detected(found)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;
    use std::io::Write;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// `ConnOpts` is `Args`, not `Parser`, so tests need a root command to
    /// flatten it into — the same shape `main.rs` uses.
    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        conn: ConnOpts,
    }

    fn parse(args: &[&str]) -> ConnOpts {
        let mut full = vec!["kcs-migrator"];
        full.extend_from_slice(args);
        TestCli::try_parse_from(full)
            .expect("args should parse")
            .conn
    }

    /// Builds options directly, bypassing clap.
    ///
    /// Needed because `token` carries `env = "KCS_TOKEN"`: any test that asserts
    /// behaviour when *no* token was supplied would otherwise pass or fail
    /// depending on whether the developer happens to have that variable
    /// exported. Tests must not read the ambient environment.
    fn opts_without_token(url: &str) -> ConnOpts {
        ConnOpts {
            url: url.to_string(),
            token: None,
            token_file: None,
            no_verify_tls: true,
            host_header: None,
            api_version: ApiVersionArg::Auto,
            timeout_secs: 120,
            connect_timeout_secs: 10,
        }
    }

    fn token_file(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write");
        f.flush().expect("flush");
        f
    }

    // ---- token resolution ----

    #[test]
    fn token_comes_from_the_flag_when_that_is_all_there_is() -> Result<()> {
        assert_eq!(resolve_token(Some("kcs_abc"), None)?, "kcs_abc");
        Ok(())
    }

    #[test]
    fn token_file_is_read_and_trimmed() -> Result<()> {
        // What `echo kcs_abc > token.txt` actually produces.
        let f = token_file("kcs_abc\n");
        assert_eq!(resolve_token(None, Some(f.path()))?, "kcs_abc");
        Ok(())
    }

    #[test]
    fn token_file_takes_only_the_first_line() -> Result<()> {
        // A trailing newline in an HTTP header value is a request-smuggling
        // primitive, so only the first line is ever used.
        let f = token_file("kcs_abc\nkcs_this_is_ignored\n");
        assert_eq!(resolve_token(None, Some(f.path()))?, "kcs_abc");
        Ok(())
    }

    #[test]
    fn token_file_wins_over_the_flag() -> Result<()> {
        let f = token_file("from_file\n");
        assert_eq!(
            resolve_token(Some("from_flag"), Some(f.path()))?,
            "from_file"
        );
        Ok(())
    }

    #[test]
    fn empty_token_file_is_an_error_naming_the_path() {
        let f = token_file("\n   \n");
        let err = resolve_token(None, Some(f.path())).expect_err("empty file must fail");
        let rendered = format!("{err}");
        assert!(
            rendered.contains(&f.path().display().to_string()),
            "error should name the file, got: {rendered}"
        );
    }

    #[test]
    fn missing_token_file_is_an_error_naming_the_path() {
        let err = resolve_token(None, Some(Path::new("/nonexistent/kcs.token")))
            .expect_err("missing file must fail");
        assert!(format!("{err}").contains("/nonexistent/kcs.token"));
    }

    #[test]
    fn no_token_anywhere_names_all_three_sources() {
        let err = resolve_token(None, None).expect_err("no token must fail");
        let rendered = format!("{err}");
        for source in ["--token-file", "--token", "KCS_TOKEN"] {
            assert!(
                rendered.contains(source),
                "error should name {source}, got: {rendered}"
            );
        }
    }

    #[test]
    fn whitespace_only_token_flag_is_treated_as_absent() {
        assert!(resolve_token(Some("   "), None).is_err());
    }

    // ---- flag surface ----

    #[test]
    fn api_version_defaults_to_auto() {
        let o = parse(&["--url", "https://kcs.demo.lab/api"]);
        assert_eq!(o.api_version, ApiVersionArg::Auto);
        assert_eq!(o.api_version.pinned(), None);
    }

    #[test]
    fn api_version_accepts_v1_and_v3() {
        assert_eq!(
            parse(&["--url", "u", "--api-version", "v1"])
                .api_version
                .pinned(),
            Some(ApiVersion::V1)
        );
        assert_eq!(
            parse(&["--url", "u", "--api-version", "v3"])
                .api_version
                .pinned(),
            Some(ApiVersion::V3)
        );
    }

    #[test]
    fn api_version_rejects_v2_which_the_tool_does_not_model() {
        // v2 exists on the server but no product documentation references it, so
        // there is no basis for choosing it. Rejecting it is better than guessing.
        let args = ["kcs-migrator", "--url", "u", "--api-version", "v2"];
        assert!(TestCli::try_parse_from(args).is_err());
    }

    #[test]
    fn timeout_flags_default_to_the_client_defaults() {
        let o = parse(&["--url", "u"]);
        assert_eq!(o.timeouts(), Timeouts::default());
    }

    #[test]
    fn timeout_flags_override_the_defaults() {
        let o = parse(&[
            "--url",
            "u",
            "--timeout-secs",
            "5",
            "--connect-timeout-secs",
            "2",
        ]);
        assert_eq!(
            o.timeouts(),
            Timeouts {
                connect: Duration::from_secs(2),
                request: Duration::from_secs(5),
            }
        );
    }

    // ---- §7.2 the override must not probe ----

    #[tokio::test]
    async fn explicit_api_version_sends_no_detection_request() -> Result<()> {
        // No /healthz mock at all: if `connect` probed, the request would be
        // unmatched and the generation would not be what was asked for.
        let server = MockServer::start().await;
        let opts = parse(&[
            "--url",
            &server.uri(),
            "--token",
            "tok",
            "--api-version",
            "v1",
            "--no-verify-tls",
        ]);

        let (client, resolved) = opts.connect().await?;
        assert_eq!(client.api_version(), ApiVersion::V1);
        assert_eq!(resolved, Resolved::Pinned(ApiVersion::V1));

        let requests = server.received_requests().await.unwrap_or_default();
        assert!(
            requests.is_empty(),
            "an explicit --api-version must not probe, got {} request(s)",
            requests.len()
        );
        Ok(())
    }

    #[tokio::test]
    async fn pinning_v1_against_a_2_5_instance_still_uses_v1() -> Result<()> {
        // The escape hatch for an instance whose /healthz lies or is blocked:
        // the operator's choice beats what the server would have said.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/healthz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": "2.5.0"})))
            .mount(&server)
            .await;

        let opts = parse(&[
            "--url",
            &server.uri(),
            "--token",
            "tok",
            "--api-version",
            "v1",
        ]);
        let (client, _) = opts.connect().await?;
        assert_eq!(client.api_version(), ApiVersion::V1);
        Ok(())
    }

    #[tokio::test]
    async fn auto_probes_and_pins_the_detected_generation() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/healthz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": "2.5.0"})))
            .mount(&server)
            .await;

        let opts = parse(&["--url", &server.uri(), "--token", "tok"]);
        let (client, resolved) = opts.connect().await?;
        assert_eq!(client.api_version(), ApiVersion::V3);
        assert_eq!(resolved, Resolved::Detected(KcsVersion::new(2, 5, 0)));
        assert!(!server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn connect_fails_before_any_request_when_no_token_is_supplied() -> Result<()> {
        let server = MockServer::start().await;
        let opts = opts_without_token(&server.uri());
        assert!(opts.connect().await.is_err());
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a missing token must be caught before anything is sent"
        );
        Ok(())
    }
}
