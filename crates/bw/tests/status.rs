//! Integration tests for `bw status`.
//!
//! Each test scopes the CLI's appdata to a unique tempdir via `BITWARDENCLI_APPDATA_DIR`, so the
//! suite never touches the developer's real `~/Library/Application Support/Bitwarden CLI` (or
//! platform equivalent) — and, because no session database exists there, every run is in the
//! logged-out state. The logged-in states cannot be covered here; the suite has no session fixture
//! (same limitation documented in `tests/send.rs`).

use std::{path::PathBuf, process::Command};

mod common;
use common::bw;

/// A scratch appdata directory plus a `Command` builder that targets it.
struct TempAppdata {
    dir: PathBuf,
}

impl TempAppdata {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "bw-status-it-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4(),
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        Self { dir }
    }

    fn bw(&self) -> Command {
        let mut cmd = bw();
        // `--color no` keeps the `bat` pretty-printer out of the way so stdout is plain JSON.
        cmd.args(["--color", "no"]);
        cmd.env("BITWARDENCLI_APPDATA_DIR", &self.dir);
        // `legacy_temp_login` would log in and exit(0) before the command runs.
        cmd.env_remove("BW_EMAIL");
        cmd.env_remove("BW_PASSWORD");
        cmd.env_remove("BW_SESSION");
        cmd
    }
}

impl Drop for TempAppdata {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stdout_of(cmd: &mut Command) -> String {
    let output = cmd.output().expect("Failed to execute bw command");
    assert!(
        output.status.success(),
        "Command failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("stdout is valid UTF-8")
}

fn status_json(app: &TempAppdata) -> serde_json::Value {
    let stdout = stdout_of(app.bw().arg("status"));
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("status is not JSON ({e}): {stdout}"))
}

#[test]
fn status_when_logged_out_reports_unauthenticated_and_the_default_server() {
    let app = TempAppdata::new();

    let json = status_json(&app);

    assert_eq!(json["status"], "unauthenticated");
    assert_eq!(json["serverUrl"], "https://bitwarden.com");
    assert!(json["lastSync"].is_null(), "got: {json}");
    assert!(json["userEmail"].is_null(), "got: {json}");
    assert!(json["userId"].is_null(), "got: {json}");
}

#[test]
fn status_reports_the_server_set_by_config_server() {
    let app = TempAppdata::new();
    stdout_of(
        app.bw()
            .args(["config", "server", "https://self.example.com"]),
    );

    let json = status_json(&app);

    assert_eq!(json["serverUrl"], "https://self.example.com");
}
