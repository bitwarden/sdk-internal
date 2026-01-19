//! CLI integration tests for version command
//!
//! Simple test to verify the CLI binary runs and returns version information

use std::process::Command;

use rexpect::session::{PtySession, spawn_command};

/// Spawn the bw binary with the given arguments
fn spawn_bw(args: &[&str]) -> PtySession {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bw"));
    cmd.args(args);
    spawn_command(cmd, Some(5000)).expect("Failed to spawn bw")
}

/// Assert that the output contains expected version information
fn assert_version_output(p: &mut PtySession) {
    p.exp_string("Bitwarden CLI")
        .expect("Should contain 'Bitwarden CLI'");
    p.exp_string(env!("CARGO_PKG_VERSION"))
        .expect("Should contain version");
    p.exp_eof().expect("Process should exit");
}

/// Test that the CLI binary exists and responds to --version
#[test]
fn test_cli_version() {
    let mut p = spawn_bw(&["--version"]);
    assert_version_output(&mut p);
}

/// Test that -v flag also returns version
#[test]
fn test_cli_version_short_flag() {
    let mut p = spawn_bw(&["-v"]);
    assert_version_output(&mut p);
}
