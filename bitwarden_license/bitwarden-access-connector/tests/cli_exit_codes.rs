//! Pins the `bwac` binary's exit codes for command-line argument errors: they must not collide with
//! the credential-refused code (2), and `--help` / `--version` must still exit 0.

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
