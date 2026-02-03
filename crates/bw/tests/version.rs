//! Tests for the bw CLI version flags

mod common;
use common::bw;

/// Helper function to test version output
fn assert_version_output(args: &[&str]) {
    let output = bw()
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
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "Output should contain version '{}': {}",
        env!("CARGO_PKG_VERSION"),
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
