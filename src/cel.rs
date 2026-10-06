//! # Overview
//!
//! CEL rules as editable text files.
//!
//! KCS 2.5 lets operators write their own benchmark controls, assurance
//! controls and admission controls in CEL. The API carries each rule as a
//! JSON string in a `rule` field, which means a multi-line expression
//! arrives as one line full of escaped newlines and quotes — unreadable, and
//! impossible to review in a diff.
//!
//! Export therefore writes each rule to `CEL/<resource>/<slug>.cel`
//! verbatim and leaves a pointer in its place:
//!
//! ```json
//! { "name": "no-root-containers", "rule": { "$celFile": "CEL/benchmark/control/CTRL-0001.cel" } }
//! ```
//!
//! Import reads the file back and restores the string before `POSTing`.
//! That is what makes the rules editable by hand between export and
//! import, which is the point of keeping them outside the JSON.
//!
//! # The pointer is untrusted input
//!
//! A bundle is a directory the operator is explicitly invited to edit, so
//! a `$celFile` value is attacker-influenced in the same sense any
//! config file is. [`resolve_path`] rejects absolute paths and any path
//! containing `..`, so a pointer cannot read outside its bundle.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

/// The key that marks a value as a reference to a `.cel` file.
pub const POINTER_KEY: &str = "$celFile";

/// Field holding the CEL expression on every resource that has one.
const RULE_FIELD: &str = "rule";

/// Turns a resource name or control ID into a safe file stem.
///
/// Anything outside `[A-Za-z0-9._-]` becomes `_`. The result is a
/// filename and never an identifier — the JSON entry keeps the pointer,
/// so nothing downstream parses the slug back into a name.
fn slugify(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Collapse any `..` left over. A `..` inside a single filename component
    // cannot traverse anything — `resolve_path` is what enforces that, and it
    // checks path components, not substrings. It is collapsed anyway because a
    // path that *reads* like an escape invites a later reader to "harden" it in
    // the wrong place, and because `_.._etc_passwd.cel` is not a name anyone
    // wants to see in a bundle they are reviewing.
    let mut collapsed = cleaned;
    while collapsed.contains("..") {
        collapsed = collapsed.replace("..", "_");
    }

    // A leading dot would make the file hidden — invisible to an operator
    // editing the bundle — and an empty stem would produce a bare ".cel".
    let trimmed = collapsed.trim_matches('.').trim_matches('_').to_string();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed
    }
}

/// Picks the slug source for an item: `controlId` if it has one, else
/// `name`.
fn slug_for(item: &Value) -> String {
    let raw = item
        .get("controlId")
        .and_then(Value::as_str)
        .or_else(|| item.get("name").and_then(Value::as_str))
        .unwrap_or("unnamed");
    slugify(raw)
}

/// # Overview
///
/// Joins a bundle-relative path onto `bundle`, refusing anything that
/// could escape it.
///
/// # Errors
///
/// Returns an error for an absolute path, a path containing `..`, or one
/// with a Windows prefix or root component. Rejecting rather than
/// sanitising is deliberate: a pointer that needed rewriting to be safe
/// is a pointer nobody intended, so the operator should see it.
///
/// # Examples
///
/// ```
/// use kcs_migrator::cel;
/// use std::path::Path;
///
/// let bundle = Path::new("/tmp/kcs-export-x");
/// let ok = cel::resolve_path(bundle, "CEL/benchmark/control/CTRL-1.cel")?;
/// assert!(ok.starts_with(bundle));
///
/// // A bundle is hand-editable before import, so its paths are untrusted.
/// assert!(cel::resolve_path(bundle, "../../etc/passwd").is_err());
/// assert!(cel::resolve_path(bundle, "/etc/passwd").is_err());
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn resolve_path(bundle: &Path, rel: &str) -> Result<PathBuf> {
    let candidate = Path::new(rel);
    if candidate.is_absolute() {
        return Err(anyhow!(
            "CEL reference {rel:?} is an absolute path; bundle references must be \
             relative to the bundle directory"
        ));
    }
    for component in candidate.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(anyhow!(
                    "CEL reference {rel:?} escapes the bundle with '..'; refusing to read \
                     outside {}",
                    bundle.display()
                ))
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(anyhow!("CEL reference {rel:?} is not a relative path"))
            }
        }
    }
    Ok(bundle.join(candidate))
}

/// # Overview
///
/// Moves each item's `rule` into `CEL/<rel_dir>/<slug>.cel` and replaces
/// it with a `$celFile` pointer.
///
/// `items` is the resource array as exported. Items with no `rule`, or a
/// non-string one, are left alone. Returns how many rules were extracted.
///
/// Colliding slugs get a `-2`, `-3` suffix, so two controls named
/// `check/root` and `check:root` do not overwrite each other.
///
/// # Errors
///
/// Returns an error if a directory or file cannot be written.
pub fn extract(items: &mut Value, bundle: &Path, rel_dir: &str) -> Result<usize> {
    let Some(array) = items.as_array_mut() else {
        return Ok(0);
    };

    let dir_rel = format!("CEL/{rel_dir}");
    let dir_abs = bundle.join(&dir_rel);
    let mut used: HashMap<String, u32> = HashMap::new();
    let mut extracted = 0;

    for item in array.iter_mut() {
        let Some(rule) = item.get(RULE_FIELD).and_then(Value::as_str) else {
            continue;
        };
        let rule = rule.to_string();

        let stem = slug_for(item);
        // `entry` needs an owned key, so this clones the stem once per entry even
        // when the key is already present. That is deliberate: avoiding it means
        // a `get_mut`/`insert` pair, which clippy flags and whose suggested
        // rewrite does not compile (the closure would borrow `used` a second
        // time). One short String per control is not worth that.
        let seen = used.entry(stem.clone()).or_insert(0);
        *seen += 1;
        let file_stem = if *seen == 1 {
            stem
        } else {
            format!("{stem}-{seen}")
        };
        let file_rel = format!("{dir_rel}/{file_stem}.cel");

        std::fs::create_dir_all(&dir_abs)
            .with_context(|| format!("failed to create {}", dir_abs.display()))?;
        let file_abs = bundle.join(&file_rel);
        std::fs::write(&file_abs, &rule)
            .with_context(|| format!("failed to write {}", file_abs.display()))?;

        if let Some(obj) = item.as_object_mut() {
            obj.insert(RULE_FIELD.to_string(), json!({ POINTER_KEY: file_rel }));
        }
        extracted += 1;
    }

    Ok(extracted)
}

/// # Overview
///
/// Replaces each item's `$celFile` pointer with the file's contents,
/// ready to POST.
///
/// Items whose `rule` is already a plain string are left alone, so a
/// hand-written bundle that inlines its rules still imports.
///
/// # Errors
///
/// Returns an error if a pointer escapes the bundle (see
/// [`resolve_path`]), names a file that does not exist, or names a file
/// that cannot be read as UTF-8.
pub fn inline(items: &mut Value, bundle: &Path) -> Result<usize> {
    let Some(array) = items.as_array_mut() else {
        return Ok(0);
    };
    let mut inlined = 0;

    for item in array.iter_mut() {
        let Some(rel) = item
            .get(RULE_FIELD)
            .and_then(|r| r.get(POINTER_KEY))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let rel = rel.to_string();

        let path = resolve_path(bundle, &rel)?;
        let rule = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "CEL reference {rel:?} points at {}, which could not be read",
                path.display()
            )
        })?;

        if let Some(obj) = item.as_object_mut() {
            obj.insert(RULE_FIELD.to_string(), Value::String(rule));
        }
        inlined += 1;
    }

    Ok(inlined)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CEL expression with the characters that break naive escaping:
    /// newlines, double quotes and backslashes.
    const GNARLY_RULE: &str = r#"object.spec.containers.all(c,
  c.securityContext.runAsNonRoot == true &&
  !c.image.contains("latest") &&
  c.name.matches("^[a-z\\-]+$")
)"#;

    #[test]
    fn a_rule_round_trips_through_a_file_byte_for_byte() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let bundle = tmp.path();
        let mut items = json!([{
            "controlId": "CTRL-0001",
            "name": "no root containers",
            "rule": GNARLY_RULE,
        }]);

        let extracted = extract(&mut items, bundle, "benchmark/control")?;
        assert_eq!(extracted, 1);

        // The JSON now holds a pointer, and the file holds the rule verbatim.
        assert_eq!(
            items[0]["rule"][POINTER_KEY],
            json!("CEL/benchmark/control/CTRL-0001.cel")
        );
        let on_disk = std::fs::read_to_string(bundle.join("CEL/benchmark/control/CTRL-0001.cel"))?;
        assert_eq!(on_disk, GNARLY_RULE, "written verbatim, no re-escaping");

        let inlined = inline(&mut items, bundle)?;
        assert_eq!(inlined, 1);
        assert_eq!(
            items[0]["rule"],
            json!(GNARLY_RULE),
            "the string the API gave us is the string it gets back"
        );
        Ok(())
    }

    #[test]
    fn control_id_is_preferred_over_name_for_the_file_stem() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut items = json!([{"controlId": "CTRL-0042", "name": "ignored", "rule": "true"}]);
        extract(&mut items, tmp.path(), "benchmark/control")?;
        assert!(items[0]["rule"][POINTER_KEY]
            .as_str()
            .unwrap_or_default()
            .ends_with("CTRL-0042.cel"));
        Ok(())
    }

    #[test]
    fn name_is_used_when_there_is_no_control_id() -> Result<()> {
        // Assurance and admission controls have no controlId.
        let tmp = tempfile::tempdir()?;
        let mut items = json!([{"name": "block-latest-tag", "rule": "true"}]);
        extract(&mut items, tmp.path(), "policies/assurance-control")?;
        assert_eq!(
            items[0]["rule"][POINTER_KEY],
            json!("CEL/policies/assurance-control/block-latest-tag.cel")
        );
        Ok(())
    }

    #[test]
    fn unsafe_characters_in_a_name_become_a_safe_file_stem() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut items = json!([{"name": "../../etc/passwd", "rule": "true"}]);
        extract(&mut items, tmp.path(), "policies/assurance-control")?;

        let pointer = items[0]["rule"][POINTER_KEY]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            pointer, "CEL/policies/assurance-control/etc_passwd.cel",
            "separators are flattened and `..` collapsed into the stem"
        );

        // The property that actually matters: the stem is ONE path component, so
        // a resource name can never become path structure.
        let stem = Path::new(&pointer)
            .file_name()
            .ok_or_else(|| anyhow!("pointer has no file name"))?;
        assert_eq!(
            Path::new(stem).components().count(),
            1,
            "the slug must be a single component"
        );

        // And it resolves to a real file inside the bundle, not outside it.
        let resolved = resolve_path(tmp.path(), &pointer)?;
        assert!(resolved.exists());
        assert!(
            resolved
                .canonicalize()?
                .starts_with(tmp.path().canonicalize()?),
            "resolved path must stay inside the bundle"
        );
        Ok(())
    }

    #[test]
    fn colliding_slugs_get_distinct_files() -> Result<()> {
        // Two different names that slugify identically must not overwrite
        // each other -- the second rule would silently become the first.
        let tmp = tempfile::tempdir()?;
        let mut items = json!([
            {"name": "check/root", "rule": "first"},
            {"name": "check:root", "rule": "second"},
            {"name": "check root", "rule": "third"},
        ]);
        extract(&mut items, tmp.path(), "benchmark/control")?;

        let pointers: Vec<String> = items
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|i| {
                i["rule"][POINTER_KEY]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        assert_eq!(pointers.len(), 3);
        let unique: std::collections::HashSet<&String> = pointers.iter().collect();
        assert_eq!(
            unique.len(),
            3,
            "each rule needs its own file: {pointers:?}"
        );

        inline(&mut items, tmp.path())?;
        assert_eq!(items[0]["rule"], json!("first"));
        assert_eq!(items[1]["rule"], json!("second"));
        assert_eq!(items[2]["rule"], json!("third"));
        Ok(())
    }

    #[test]
    fn an_empty_or_dotted_name_still_produces_a_usable_filename() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut items = json!([{"name": "...", "rule": "a"}, {"name": "", "rule": "b"}]);
        extract(&mut items, tmp.path(), "benchmark/control")?;
        for i in 0..2 {
            let p = items[i]["rule"][POINTER_KEY]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(!p.ends_with("/.cel"), "no bare .cel: {p}");
            assert!(
                !p.contains("/."),
                "no hidden file, which an operator would not see when editing: {p}"
            );
        }
        Ok(())
    }

    // ---- the pointer is untrusted ----

    #[test]
    fn a_pointer_with_a_parent_dir_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err =
            resolve_path(tmp.path(), "CEL/../../../etc/passwd").expect_err("'..' must be refused");
        let rendered = format!("{err}");
        assert!(rendered.contains("escapes the bundle"), "got: {rendered}");
    }

    #[test]
    fn an_absolute_pointer_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = resolve_path(tmp.path(), "/etc/passwd").expect_err("absolute must be refused");
        assert!(format!("{err}").contains("absolute path"));
    }

    #[test]
    fn inline_refuses_a_traversing_pointer_rather_than_reading_the_file() -> Result<()> {
        // The bundle is a directory the operator is invited to edit, so this is
        // reachable input, not an impossible state.
        let tmp = tempfile::tempdir()?;
        let mut items = json!([{"name": "evil", "rule": {POINTER_KEY: "../../../etc/passwd"}}]);
        let err = inline(&mut items, tmp.path()).expect_err("traversal must be refused");
        assert!(format!("{err}").contains("escapes the bundle"));
        Ok(())
    }

    #[test]
    fn inline_reports_a_pointer_whose_file_is_missing() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut items =
            json!([{"name": "x", "rule": {POINTER_KEY: "CEL/benchmark/control/gone.cel"}}]);
        let err = inline(&mut items, tmp.path()).expect_err("a missing file must fail");
        let rendered = format!("{err}");
        assert!(rendered.contains("gone.cel"), "names the file: {rendered}");
        Ok(())
    }

    // ---- shapes that must pass through untouched ----

    #[test]
    fn an_already_inline_rule_is_left_alone_by_inline() -> Result<()> {
        // A hand-written bundle may skip the indirection entirely.
        let tmp = tempfile::tempdir()?;
        let mut items = json!([{"name": "x", "rule": "object.spec != null"}]);
        let before = items.clone();
        assert_eq!(inline(&mut items, tmp.path())?, 0);
        assert_eq!(items, before);
        Ok(())
    }

    #[test]
    fn items_without_a_rule_are_untouched() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut items = json!([{"name": "no-rule-here", "severity": "high"}]);
        let before = items.clone();
        assert_eq!(extract(&mut items, tmp.path(), "benchmark/control")?, 0);
        assert_eq!(items, before);
        assert_eq!(inline(&mut items, tmp.path())?, 0);
        assert_eq!(items, before);
        // Nothing was created for a resource class with no rules.
        assert!(!tmp.path().join("CEL").exists());
        Ok(())
    }

    #[test]
    fn a_non_array_input_is_a_no_op_not_a_panic() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        for mut items in [json!({}), json!(null), json!("nonsense")] {
            assert_eq!(extract(&mut items, tmp.path(), "benchmark/control")?, 0);
            assert_eq!(inline(&mut items, tmp.path())?, 0);
        }
        Ok(())
    }
}
