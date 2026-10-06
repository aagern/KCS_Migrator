#![forbid(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        // Tests assert by panicking; a non-exhaustive match arm that should never be
        // reached is clearer as `panic!` than as a contrived fallback value.
        clippy::panic
    )
)]
// pedantic; `version::KcsVersion` and `client::KcsClient` read better than `version::Kcs`:
#![allow(clippy::module_name_repetitions)]
// pedantic; every public fn here already carries a hand-written `# Errors` section, and the
// lint also fires on private helpers where that docblock would be noise:
#![allow(clippy::missing_errors_doc)]

//! # Overview
//!
//! `kcs_migrator` is a two-phase migration toolkit for the KCS
//! (Kaspersky Container Security) configuration surface. It exposes the
//! reusable pieces of the `kcs-migrator` CLI as a library so they can be
//! consumed from integration tests, doctests, or downstream tooling.
//!
//! Phase one — [`export::export_all`] — pulls every replayable resource
//! from a source KCS instance and writes a self-contained, timestamped
//! bundle directory.
//!
//! Phase two — [`importer::import_bundle`] — replays a bundle onto a
//! target instance in a fixed dependency order, rewriting cross-resource
//! IDs via the in-memory [`id_mapper::IdMapper`] registry as it goes.
//!
//! # Module map
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`cli`]       | Connection options shared by the subcommands, and how they become a client. |
//! | [`client`]    | Async [`reqwest`] wrapper that injects the `Tron-Token` auth header. |
//! | [`export`]    | Dumps a source KCS to a versioned bundle directory. |
//! | [`importer`]  | Replays a bundle onto a target KCS in dependency order. |
//! | [`id_mapper`] | Source→target ID registry used during import to rewrite FK fields. |
//! | [`translate`] | Rewrites bundle bodies between API generations (forward-only, v1 to v3). |
//! | [`users`]     | Reference-only user export via `kubectl exec` against the KCS Postgres pod. |
//! | [`version`]   | Which API generation an instance speaks, and how to tell from its release. |
//!
//! # API generations
//!
//! KCS serves several API generations side by side. KCS 2.4 and earlier
//! only have `/api/v1/`; 2.5 added `/api/v3/` and keeps `v1` as a
//! compatibility shim; 2.6 deprecates `v1`. The migrator detects the
//! target's release from `GET /{v}/healthz` and picks a generation —
//! see [`version::ApiVersion::for_kcs`].
//!
//! # Examples
//!
//! ```no_run
//! use kcs_migrator::client::{KcsClient, Timeouts};
//! use kcs_migrator::{export, importer};
//! use std::path::Path;
//!
//! # async fn run() -> anyhow::Result<()> {
//! // `detect` probes the instance's release and pins the client to the
//! // matching API generation.
//! let (source, src_kcs) = KcsClient::detect(
//!     "https://kcs.src.corp", "tok", true, None, Timeouts::default(),
//! ).await?;
//! let bundle = export::export_all(&source, Path::new(".")).await?;
//!
//! let (target, tgt_kcs) = KcsClient::detect(
//!     "https://kcs.tgt.corp", "tok", true, None, Timeouts::default(),
//! ).await?;
//! println!("migrating KCS {src_kcs} → KCS {tgt_kcs}");
//! let mapper = importer::import_bundle(
//!     &target, &bundle, &importer::ImportOptions::default(),
//! ).await?;
//! # Ok(())
//! # }
//! ```

pub mod cli;
pub mod client;
pub mod export;
pub mod id_mapper;
pub mod importer;
pub mod translate;
pub mod users;
pub mod version;
