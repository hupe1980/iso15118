//! What every live-peer test shares: the report a container prints, the
//! rules a row has to obey, and the table a maintainer reads.
//!
//! The unit is a row — one session, one peer, one role, one generation, one
//! service. A row passes only when both ends reached a normal close after
//! `SessionStop` and nothing failed to decode; it is skipped only when a
//! prerequisite is missing, never because a peer answered wrongly.

#![allow(dead_code, reason = "each live-peer test uses part of this")]

use serde_json::Value;

/// The marker a container prints before its JSON array of rows.
pub(crate) const REPORT_MARKER: &str = "INTEROP-REPORT ";

/// Whether a Docker daemon that runs Linux containers answers. Without one
/// the peer is skipped by name — a Windows daemon in Windows-container mode
/// answers too, and cannot build the image.
pub(crate) fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["info", "--format", "{{.OSType}}"])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "linux")
}

/// One row, as the container reported it.
#[derive(Debug, Clone)]
pub(crate) struct Row {
    pub(crate) peer: String,
    pub(crate) peer_version: String,
    pub(crate) role: String,
    pub(crate) generation: String,
    pub(crate) service: String,
    pub(crate) auth: String,
    pub(crate) tls: bool,
    pub(crate) outcome: String,
    pub(crate) reason: Option<String>,
    pub(crate) messages: u64,
    pub(crate) elapsed_ms: u64,
}

fn text(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("row without {key}: {v}"))
}

impl Row {
    fn from_json(v: &Value) -> Result<Self, String> {
        let row = Self {
            peer: text(v, "peer")?,
            peer_version: text(v, "peer_version")?,
            role: text(v, "role")?,
            generation: text(v, "generation")?,
            service: text(v, "service")?,
            auth: text(v, "auth")?,
            tls: v.get("tls").and_then(Value::as_bool).unwrap_or(false),
            outcome: text(v, "outcome")?,
            reason: v.get("reason").and_then(Value::as_str).map(str::to_owned),
            messages: v.get("messages").and_then(Value::as_u64).unwrap_or(0),
            elapsed_ms: v.get("elapsed_ms").and_then(Value::as_u64).unwrap_or(0),
        };
        if !matches!(row.outcome.as_str(), "pass" | "fail" | "skip") {
            return Err(format!("{}: unknown outcome {}", row.name(), row.outcome));
        }
        if row.outcome != "pass" && row.reason.as_deref().is_none_or(str::is_empty) {
            return Err(format!("{}: a row that did not pass must say why", row.name()));
        }
        Ok(row)
    }

    pub(crate) fn name(&self) -> String {
        format!(
            "{} {} — ours {} {} {} {}{}",
            self.peer,
            self.peer_version,
            self.role,
            self.generation,
            self.service,
            self.auth,
            if self.tls { " TLS" } else { "" }
        )
    }
}

/// Finds the last report line in a container's output.
///
/// A container that did not report has not passed.
pub(crate) fn parse_report(stdout: &str) -> Result<Vec<Row>, String> {
    let line = stdout
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix(REPORT_MARKER))
        .ok_or_else(|| "the container did not report".to_string())?;
    let rows: Vec<Value> = serde_json::from_str(line).map_err(|e| format!("bad report: {e}"))?;
    if rows.is_empty() {
        return Err("the container reported no rows".into());
    }
    rows.iter().map(Row::from_json).collect()
}

/// The container's output without the report line, which the table replaces.
pub(crate) fn without_report(stdout: &str) -> String {
    let mut out = String::new();
    for line in stdout.lines().filter(|l| !l.starts_with(REPORT_MARKER)) {
        out.push_str(line);
        out.push('\n');
    }
    out
}

pub(crate) fn print_table(rows: &[Row]) {
    println!(
        "{:<7} {:<9} {:<5} {:<6} {:<4} {:<4} {:<4} {:<5} {:>5} {:>7}  reason",
        "peer", "version", "ours", "gen", "svc", "auth", "tls", "out", "msgs", "ms"
    );
    for r in rows {
        println!(
            "{:<7} {:<9} {:<5} {:<6} {:<4} {:<4} {:<4} {:<5} {:>5} {:>7}  {}",
            r.peer,
            r.peer_version,
            r.role,
            r.generation,
            r.service,
            r.auth,
            if r.tls { "yes" } else { "no" },
            r.outcome,
            r.messages,
            r.elapsed_ms,
            r.reason.as_deref().unwrap_or("")
        );
    }
}

/// Fails naming every row that failed. A skipped row is printed, not failed:
/// it is a missing prerequisite on this machine, and it says which.
pub(crate) fn assert_all_passed(peer: &str, rows: &[Row]) {
    let failed: Vec<String> = rows
        .iter()
        .filter(|r| r.outcome == "fail")
        .map(|r| format!("  {}: {}", r.name(), r.reason.as_deref().unwrap_or("")))
        .collect();
    assert!(failed.is_empty(), "{peer}: {} row(s) failed\n{}", failed.len(), failed.join("\n"));
}
