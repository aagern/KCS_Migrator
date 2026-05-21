use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

const SQL: &str = "SELECT username, COALESCE(email,''), COALESCE(display_name,''),\
 roles, user_type, identity_provider, active::text FROM users ORDER BY username;";

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
    let mut users = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(7, '|').collect();
        if parts.len() != 7 {
            continue;
        }
        users.push(json!({
            "username": parts[0],
            "email": parts[1],
            "display_name": parts[2],
            "roles": parts[3],
            "user_type": parts[4],
            "identity_provider": parts[5],
            "active": parts[6] == "true",
        }));
    }

    let out_path = output_dir.join("users-REFERENCE.json");
    std::fs::write(&out_path, serde_json::to_string_pretty(&users)?)?;

    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_psql_output_into_user_records() {
        // Simulate what export_users_reference parses from stdout.
        // We test the parsing logic directly without invoking kubectl.
        let raw = "admin||Admin User|[\"admin\"]|local|local|true\noperator|op@corp.com|Operator|[\"viewer\"]|local|local|false\n";
        let mut users = Vec::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(7, '|').collect();
            if parts.len() != 7 {
                continue;
            }
            users.push(json!({
                "username": parts[0],
                "email": parts[1],
                "display_name": parts[2],
                "roles": parts[3],
                "user_type": parts[4],
                "identity_provider": parts[5],
                "active": parts[6] == "true",
            }));
        }

        assert_eq!(users.len(), 2);
        assert_eq!(users[0]["username"], "admin");
        assert_eq!(users[0]["active"], true);
        assert_eq!(users[1]["email"], "op@corp.com");
        assert_eq!(users[1]["active"], false);
    }

    #[test]
    fn empty_psql_output_returns_empty_vec() {
        let raw = "\n\n";
        let users: Vec<Value> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| {
                let parts: Vec<&str> = line.splitn(7, '|').collect();
                if parts.len() != 7 { return None; }
                Some(json!({"username": parts[0]}))
            })
            .collect();
        assert!(users.is_empty());
    }
}
