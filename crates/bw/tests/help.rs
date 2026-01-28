//! Tests for the bw CLI help functionality

use std::process::Command;

#[test]
fn test_no_args_shows_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_bw"))
        .output()
        .expect("Failed to execute bw command");

    assert!(output.status.success(), "Command should exit successfully");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("Usage:"),
        "Output should contain 'Usage:': {}",
        stdout
    );
    assert!(
        stdout.contains("Commands:"),
        "Output should contain 'Commands:': {}",
        stdout
    );
    assert!(
        stdout.contains("Options:"),
        "Output should contain 'Options:': {}",
        stdout
    );
}
