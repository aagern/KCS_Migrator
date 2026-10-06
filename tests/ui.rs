//! Compile-fail tests.
//!
//! Everything else in this crate's suite proves that correct code works.
//! These prove that two specific *incorrect* uses of [`IdMapper`] do not
//! compile — which no amount of passing tests can establish, because the
//! code in question is never built.
//!
//! The guarantees being pinned:
//!
//! 1. A target ID handed out by `resolve` cannot outlive the mapper it came
//!    from. `resolve` returns `&str` borrowed from `&self`, so the mapper
//!    must still be alive wherever that string is used.
//! 2. That `&str` cannot be held across a `register` call. `register` takes
//!    `&mut self`, and the shared borrow from `resolve` is still live, so
//!    the two cannot overlap.
//!
//! The second is the one that matters in practice: the importer resolves a
//! foreign key and registers new IDs inside the same loop. Returning
//! `String` instead would make both of these compile, at the cost of an
//! allocation per rewrite and of losing the compile-time guarantee.
//!
//! # Maintenance
//!
//! The expected `.stderr` files contain rustc's own diagnostics, which
//! change wording between toolchains. If these fail after a Rust upgrade,
//! check that the *error code and span* are still what we expect, then
//! regenerate with:
//!
//! ```sh
//! TRYBUILD=overwrite cargo test --test ui
//! ```
//!
//! Do not regenerate without reading the diff: a case that starts failing
//! for a new reason, or stops failing entirely, is a real regression in the
//! guarantee rather than a stale snapshot.

#[test]
fn borrows_of_the_mapper_are_enforced_at_compile_time() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
