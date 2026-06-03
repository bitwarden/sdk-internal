//! Integration tests for `bw config server`.
//!
//! Each test scopes the CLI's appdata to a unique tempdir via
//! `BITWARDENCLI_APPDATA_DIR`, so the suite never touches the developer's
//! real `~/Library/Application Support/Bitwarden CLI` (or platform equivalent).

use std::{
    path::{Path, PathBuf},
    process::Command,
};

mod common;
use common::bw;

/// A scratch appdata directory plus a `Command` builder that targets it.
struct TempAppdata {
    dir: PathBuf,
}

impl TempAppdata {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "bw-config-it-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4(),
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        Self { dir }
    }

    fn bw(&self) -> Command {
        let mut cmd = bw();
        cmd.env("BITWARDENCLI_APPDATA_DIR", &self.dir);
        cmd
    }

    fn config_json(&self) -> PathBuf {
        self.dir.join("config.json")
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

fn read_config(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).expect("config.json should exist");
    serde_json::from_slice(&bytes).expect("config.json should parse")
}

#[test]
fn config_server_get_returns_default_when_no_file() {
    let app = TempAppdata::new();
    let stdout = stdout_of(app.bw().args(["config", "server"]));
    assert_eq!(stdout.trim(), "https://bitwarden.com");
    assert!(
        !app.config_json().exists(),
        "GET must not create config.json"
    );
}

#[test]
fn config_server_set_then_get_roundtrips_url() {
    let app = TempAppdata::new();

    let set = stdout_of(
        app.bw()
            .args(["config", "server", "https://self.example.com"]),
    );
    assert!(
        set.contains("Saved setting"),
        "SET output should confirm save, got: {set}"
    );

    let get = stdout_of(app.bw().args(["config", "server"]));
    assert_eq!(get.trim(), "https://self.example.com");
}

#[test]
fn config_server_set_normalizes_url() {
    let app = TempAppdata::new();

    // No scheme + trailing slash; format_url should add https:// and strip the slash.
    stdout_of(app.bw().args(["config", "server", "bw.example.com/"]));

    let get = stdout_of(app.bw().args(["config", "server"]));
    assert_eq!(get.trim(), "https://bw.example.com");
}

#[test]
fn config_server_set_with_default_alias_collapses_to_default() {
    let app = TempAppdata::new();

    stdout_of(
        app.bw()
            .args(["config", "server", "https://bitwarden.com"]),
    );

    let get = stdout_of(app.bw().args(["config", "server"]));
    assert_eq!(get.trim(), "https://bitwarden.com");

    let cfg = read_config(&app.config_json());
    assert!(
        cfg.get("server").is_none_or(serde_json::Value::is_null),
        "alias should collapse server to null, got: {cfg}"
    );
}

#[test]
fn config_server_set_writes_per_service_field_to_disk() {
    let app = TempAppdata::new();

    stdout_of(app.bw().args([
        "config",
        "server",
        "--api",
        "https://api.example.com",
        "--web-vault",
        "vault.example.com/",
    ]));

    let cfg = read_config(&app.config_json());
    assert_eq!(cfg["api"], "https://api.example.com");
    assert_eq!(cfg["web_vault"], "https://vault.example.com");
    // base URL was not supplied, so server stays null/absent.
    assert!(cfg.get("server").is_none_or(serde_json::Value::is_null));
}

#[test]
fn config_server_only_key_connector_takes_set_path() {
    // Pins the documented non-Node-parity behavior: passing only --key-connector
    // is treated as a SET, not a silent no-op GET.
    let app = TempAppdata::new();

    stdout_of(app.bw().args([
        "config",
        "server",
        "--key-connector",
        "https://kc.example.com",
    ]));

    assert!(
        app.config_json().exists(),
        "--key-connector alone must write config.json"
    );
    let cfg = read_config(&app.config_json());
    assert_eq!(cfg["key_connector"], "https://kc.example.com");
}

#[test]
fn config_server_get_ignores_per_service_fields_when_server_unset() {
    let app = TempAppdata::new();

    stdout_of(
        app.bw()
            .args(["config", "server", "--api", "https://api.example.com"]),
    );

    let get = stdout_of(app.bw().args(["config", "server"]));
    assert_eq!(get.trim(), "https://bitwarden.com");
}
