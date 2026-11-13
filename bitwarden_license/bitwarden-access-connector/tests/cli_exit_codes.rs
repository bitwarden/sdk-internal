//! Argument errors must not exit with the credential-refused code (2); `--help` and `--version`
//! must exit 0. A trust store with no CA certificates must exit 1 and must not panic.

use std::process::{Command, Output};

fn bwac(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bwac"))
        .args(args)
        .env_remove("BWAC_TOKEN")
        .env_remove("BWAC_CONFIG")
        .output()
        .expect("failed to run bwac")
}

#[test]
fn an_unknown_flag_exits_1_not_the_credential_refused_code() {
    assert_eq!(bwac(&["run", "--conifg", "x"]).status.code(), Some(1));
}

#[test]
fn no_subcommand_exits_1_not_the_credential_refused_code() {
    assert_eq!(bwac(&[]).status.code(), Some(1));
}

#[test]
fn help_exits_0() {
    assert_eq!(bwac(&["--help"]).status.code(), Some(0));
}

#[test]
fn version_exits_0() {
    assert_eq!(bwac(&["--version"]).status.code(), Some(0));
}

/// Only Linux reads `SSL_CERT_FILE`; macOS and Windows use the OS trust store.
#[cfg(target_os = "linux")]
#[test]
fn an_empty_trust_store_exits_1_not_a_panic() {
    // The fake token from config.rs's tests; nothing listens on port 9.
    let output = Command::new(env!("CARGO_BIN_EXE_bwac"))
        .arg("run")
        .env_remove("BWAC_CONFIG")
        .env_remove("SSL_CERT_DIR")
        .env(
            "BWAC_TOKEN",
            "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==",
        )
        .env("BWAC_API_URL", "https://127.0.0.1:9/api")
        .env("BWAC_IDENTITY_URL", "https://127.0.0.1:9/identity")
        .env("SSL_CERT_FILE", "/dev/null")
        .output()
        .expect("failed to run bwac");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("SSL_CERT_FILE"), "stderr: {stderr}");
}
