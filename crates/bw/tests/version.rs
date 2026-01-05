//! Tests for the bw CLI version flags

use std::process::Command;

/// Helper function to test version output
fn assert_version_output(args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_bw"))
        .args(args)
        .output()
        .expect("Failed to execute bw command");

    assert!(output.status.success(), "Command should exit successfully");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("Bitwarden CLI"),
        "Output should contain 'Bitwarden CLI': {}",
        stdout
    );

    assert!(
        stdout.contains("0.0.2"),
        "Output should contain version '0.0.2': {}",
        stdout
    );
}

#[test]
fn test_version_flag() {
    assert_version_output(&["--version"]);
}

#[test]
fn test_version_flag_short() {
    assert_version_output(&["-v"]);
}
