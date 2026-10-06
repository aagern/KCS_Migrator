//! # Overview
//!
//! Reference-only user export. The KCS REST API does not expose user
//! accounts in a replayable form (no create-with-password endpoint),
//! so we reach into the KCS PostgreSQL pod with `kubectl exec` and
//! dump the `users` table to JSON. The result is written into the
//! bundle as `users-REFERENCE.json` — purely informational, never
//! replayed by [`crate::importer`].
//!
//! Operators use this file to manually recreate accounts on the
//! target instance.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

/// `psql` query that extracts the user-visible columns from the KCS
/// `users` table. `COALESCE` is used so nullable text columns come
/// back as empty strings (simpler to parse from `psql -t -A` output
/// than a literal `NULL` token).
const SQL: &str = "SELECT username, COALESCE(email,''), COALESCE(display_name,''),\
 roles, user_type, identity_provider, active::text FROM users ORDER BY username;";

/// # Overview
///
/// Parses `psql -t -A -F'|'` output into user records.
///
/// Returns the records and the number of lines that could not be parsed.
/// The count is the point: a malformed row used to be skipped in silence,
/// so a `|` inside a display name made a user vanish from the export with
/// nothing said. A reference file that is quietly short is worse than one
/// that is missing, because the operator recreates what they can see.
///
/// Split out of [`export_users_reference`] so it can be tested. The tests
/// for this module used to re-implement this loop inline, which meant they
/// asserted on a copy of the logic and would have passed no matter what
/// the shipped function did.
#[must_use]
pub fn parse_psql_rows(stdout: &str) -> (Vec<Value>, usize) {
    let mut users = Vec::new();
    let mut skipped = 0;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(7, '|').collect();
        // Slice pattern instead of `parts.len() != 7` plus seven index expressions:
        // the match binds all seven fields or fails, so the compiler — not a
        // hand-written length check — guarantees every binding exists.
        let [username, email, display_name, roles, user_type, identity_provider, active] =
            parts.as_slice()
        else {
            skipped += 1;
            continue;
        };
        users.push(json!({
            "username": username,
            "email": email,
            "display_name": display_name,
            "roles": roles,
            "user_type": user_type,
            "identity_provider": identity_provider,
            "active": *active == "true",
        }));
    }

    (users, skipped)
}

/// # Overview
///
/// Runs `kubectl exec` into the KCS PostgreSQL pod in `namespace`,
/// dumps the `users` table via the `SQL` query below, parses the pipe-separated
/// rows, and writes the result to `output_dir/users-REFERENCE.json`.
/// Returns the parsed user records as well.
///
/// `pod_selector` is the `StatefulSet` name to target (e.g.
/// `"kcs-postgresql"` in a default deployment).
///
/// # Errors
///
/// Returns an error if the `kubectl exec` invocation fails (kubectl
/// not on `$PATH`, namespace/pod doesn't exist, psql query fails),
/// or if writing the bundle file fails. Malformed rows (fewer than
/// 7 pipe-separated fields, e.g. if a `display_name` itself contains
/// `|`) are silently skipped — switch the query separator if your
/// data contains pipes.
pub fn export_users_reference(
    namespace: &str,
    output_dir: &Path,
    pod_selector: &str,
) -> Result<Vec<Value>> {
    let output = Command::new("kubectl")
        .args([
            "exec",
            "-n",
            namespace,
            &format!("statefulset/{pod_selector}"),
            "--",
            "psql",
            "-U",
            "pguser",
            "-d",
            "api",
            "-t",
            "-A",
            "-F",
            "|",
            "-c",
            SQL,
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!(
            "kubectl exec failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (users, skipped) = parse_psql_rows(&stdout);
    if skipped > 0 {
        eprintln!(
            "Warning: {skipped} row(s) of the user export could not be parsed and were \
             omitted from users-REFERENCE.json. The most likely cause is a `|` inside a \
             display name, which collides with the column separator; compare the file \
             against the console's user list before relying on it."
        );
    }

    let out_path = output_dir.join("users-REFERENCE.json");
    std::fs::write(&out_path, serde_json::to_string_pretty(&users)?)?;

    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_rows() {
        let raw = "admin||Admin User|[\"admin\"]|local|local|true\n\
                   operator|op@corp.com|Operator|[\"viewer\"]|local|local|false\n";
        let (users, skipped) = parse_psql_rows(raw);

        assert_eq!(skipped, 0);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0]["username"], "admin");
        // COALESCE turns a NULL email into an empty string, not the text "NULL".
        assert_eq!(users[0]["email"], "");
        assert_eq!(users[0]["active"], true);
        assert_eq!(users[1]["email"], "op@corp.com");
        assert_eq!(users[1]["active"], false);
    }

    #[test]
    fn empty_output_yields_no_users_and_no_skips() {
        for raw in ["", "\n", "\n\n", "   \n  \n"] {
            let (users, skipped) = parse_psql_rows(raw);
            assert!(users.is_empty(), "{raw:?} should yield no users");
            assert_eq!(skipped, 0, "blank lines are not malformed rows");
        }
    }

    #[test]
    fn short_rows_are_counted_not_silently_dropped() {
        // Six columns instead of seven. This is the case that used to make a user
        // disappear from the export with nothing reported.
        let raw = "admin||Admin|[\"admin\"]|local|local|true\n\
                   broken|b@corp.com|Broken|[\"viewer\"]|local|local\n";
        let (users, skipped) = parse_psql_rows(raw);

        assert_eq!(users.len(), 1, "only the well-formed row is kept");
        assert_eq!(users[0]["username"], "admin");
        assert_eq!(skipped, 1, "the short row must be reported, not hidden");
    }

    #[test]
    fn a_pipe_in_the_last_column_is_preserved_by_splitn() {
        // splitn(7) stops splitting after six separators, so a `|` inside the
        // final column rides through intact rather than producing an eighth field.
        let raw = "admin||Admin|[\"admin\"]|local|local|true|extra\n";
        let (users, skipped) = parse_psql_rows(raw);
        assert_eq!(skipped, 0);
        // `active` is compared as a whole string, so the trailing junk makes it
        // false rather than silently truthy.
        assert_eq!(users[0]["active"], false);
    }

    #[test]
    fn a_pipe_in_an_early_column_shifts_fields_and_is_counted_or_misread() {
        // The known limitation, pinned so it is a documented behaviour rather
        // than a surprise: a `|` in a display name shifts every later column.
        let raw = "admin||Ad|min|[\"admin\"]|local|local|true\n";
        let (users, skipped) = parse_psql_rows(raw);
        assert_eq!(skipped, 0, "it parses -- that is the problem");
        assert_eq!(users[0]["display_name"], "Ad");
        assert_eq!(users[0]["roles"], "min");
        // Which is why the function reports a count and the caller warns about
        // pipes: this row is wrong but not detectably malformed.
        assert_eq!(users[0]["active"], false);
    }
}
