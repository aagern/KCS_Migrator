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
//! | [`client`]    | Async [`reqwest`] wrapper that injects the `Tron-Token` auth header. |
//! | [`export`]    | Dumps a source KCS to a versioned bundle directory. |
//! | [`importer`]  | Replays a bundle onto a target KCS in dependency order. |
//! | [`id_mapper`] | Source→target ID registry used during import to rewrite FK fields. |
//! | [`users`]     | Reference-only user export via `kubectl exec` against the KCS Postgres pod. |
//!
//! # Examples
//!
//! ```no_run
//! use kcs_migrator::client::KcsClient;
//! use kcs_migrator::{export, importer};
//! use std::path::Path;
//!
//! # async fn run() -> anyhow::Result<()> {
//! let source = KcsClient::new("https://kcs.src.corp", "tok", true, None)?;
//! let bundle = export::export_all(&source, Path::new(".")).await?;
//!
//! let target = KcsClient::new("https://kcs.tgt.corp", "tok", true, None)?;
//! let mapper = importer::import_bundle(&target, &bundle).await?;
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod export;
pub mod id_mapper;
pub mod importer;
pub mod users;
