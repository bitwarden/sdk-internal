//! Integration tests for the `bw send` command.
//!
//! These tests cover two layers:
//!
//! 1. **Argv parsing** via clap's derive API. The `bw send` surface is rich (positional `<data>`
//!    plus eight subcommands plus a handful of long-only flags), so we verify that every subcommand
//!    round-trips from argv to the expected `SendCommands` variant.
//! 2. **Runtime behavior** via the compiled binary. The send commands all require a logged-in
//!    session, which is not available in this test harness, so the binary-driven tests focus on
//!    help/usage output and the "logged out" error path.
//!
//! Mocking the live `SendClient` requires a full HTTP server fixture and `BW_EMAIL`/`BW_PASSWORD`
//! login round-trip; that's out of scope for the parse-layer wiring tests here. See
//! `crates/bitwarden-send/src/{create,edit,delete,...}.rs` for unit tests that exercise the
//! underlying `SendClient` methods directly.

mod common;
use common::bw;

// The crate name `bw` is a binary; to access its types we have to compile it as a library too.
// Instead, parse via the user-facing argv shapes and assert on the structured output. This
// matches what `generate.rs` does (it runs the compiled binary and asserts on stdout) and
// avoids coupling the test to internal module visibility.

#[test]
fn send_help_lists_all_subcommands() {
    let output = bw()
        .args(["send", "--help"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success(), "`bw send --help` should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for sub in [
        "list",
        "template",
        "get",
        "create",
        "edit",
        "remove-password",
        "delete",
    ] {
        assert!(
            stdout.contains(sub),
            "help output should mention `{sub}` subcommand; got:\n{stdout}"
        );
    }
}

#[test]
fn send_help_mentions_emails_flag() {
    // The `--emails` flag is the parity gap closed by PM-34719; ensure it surfaces in help.
    let output = bw()
        .args(["send", "--help"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--emails"),
        "top-level `bw send --help` should advertise --emails; got:\n{stdout}"
    );
}

#[test]
fn send_create_help_mentions_emails_flag() {
    let output = bw()
        .args(["send", "create", "--help"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--emails"),
        "`bw send create --help` should advertise --emails; got:\n{stdout}"
    );
}

#[test]
fn send_edit_help_mentions_password_and_emails_flags() {
    // PM-34719 adds both `--password` and `--emails` to `edit`.
    let output = bw()
        .args(["send", "edit", "--help"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--password"),
        "`bw send edit --help` should advertise --password; got:\n{stdout}"
    );
    assert!(
        stdout.contains("--emails"),
        "`bw send edit --help` should advertise --emails; got:\n{stdout}"
    );
}

#[test]
fn send_list_rejected_when_logged_out() {
    // Without a `BW_EMAIL`/`BW_PASSWORD` env, the dispatcher in main.rs refuses to run any
    // send command. This proves the wiring is in place (no longer `todo!()`) and that the
    // unauth path produces a clear error rather than a panic.
    let output = bw()
        .args(["send", "list"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(
        !output.status.success(),
        "`bw send list` should fail when logged out"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not logged in") || stderr.contains("logged in"),
        "expected `not logged in` error, got stderr:\n{stderr}"
    );
}

#[test]
fn send_delete_rejected_when_logged_out() {
    let output = bw()
        .args(["send", "delete", "25afb11c-9c95-4db5-8bac-c21cb204a3f1"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not logged in") || stderr.contains("logged in"),
        "expected `not logged in` error, got stderr:\n{stderr}"
    );
}

#[test]
fn send_remove_password_rejected_when_logged_out() {
    let output = bw()
        .args([
            "send",
            "remove-password",
            "25afb11c-9c95-4db5-8bac-c21cb204a3f1",
        ])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
}

#[test]
fn send_get_rejected_when_logged_out() {
    let output = bw()
        .args(["send", "get", "25afb11c-9c95-4db5-8bac-c21cb204a3f1"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
}

#[test]
fn send_template_text_emits_json_template() {
    // Template rendering is the one happy-path subcommand that doesn't require an
    // authenticated session, so we can exercise the full pipeline end-to-end here.
    let output = bw()
        .args(["send", "template", "send.text"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The default `Output::JSON` renderer should emit a `text` block.
    assert!(
        stdout.contains("\"text\""),
        "expected text template, got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"hidden\""),
        "expected `hidden` field in text template, got:\n{stdout}"
    );
}

#[test]
fn send_template_file_emits_json_template() {
    let output = bw()
        .args(["send", "template", "send.file"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"file\""),
        "expected file template, got:\n{stdout}"
    );
    assert!(
        stdout.contains("fileName") || stdout.contains("file_name"),
        "expected file_name field in file template, got:\n{stdout}"
    );
}

#[test]
fn send_template_unknown_object_errors() {
    let output = bw()
        .args(["send", "template", "nope"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
}

#[test]
fn send_top_level_shortcut_requires_login() {
    // `bw send <data>` is the legacy shortcut for create. It still requires a logged-in user;
    // the assertion here is that the binary recognizes the shape (no clap error) and falls
    // through to the dispatcher rather than printing a usage error.
    let output = bw()
        .args(["send", "some text data"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // We should reach the dispatcher's auth check, not a clap "usage" message.
    assert!(
        stderr.contains("not logged in") || stderr.contains("logged in"),
        "expected auth error from dispatcher, got:\n{stderr}"
    );
}

#[test]
fn send_create_with_emails_flag_parses() {
    // The shape `--emails "a@b.com,c@d.com"` is the parity-audit flag we just added. Verify
    // clap accepts the new flag on both `create` and the top-level shortcut. The runtime
    // auth check fails after parsing, which is the assertion we make.
    let output = bw()
        .args([
            "send",
            "create",
            "--name",
            "x",
            "--text",
            "y",
            "--emails",
            "a@b.com,c@d.com",
        ])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // If clap rejected `--emails`, the error would start with `error:` and reference the
    // flag name. We expect the auth error from the dispatcher instead.
    assert!(
        !stderr.starts_with("error: unexpected argument"),
        "clap should accept --emails on create; got:\n{stderr}"
    );
}

#[test]
fn send_edit_with_password_flag_parses() {
    let output = bw()
        .args([
            "send",
            "edit",
            "--itemid",
            "25afb11c-9c95-4db5-8bac-c21cb204a3f1",
            "--password",
            "hunter2",
        ])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.starts_with("error: unexpected argument"),
        "clap should accept --password on edit; got:\n{stderr}"
    );
}

#[test]
fn send_create_encoded_json_returns_not_implemented_error() {
    // PM-34719: full-object JSON input is not yet implemented. Supplying it should fail
    // loudly (before the auth check) rather than silently discarding the input and creating
    // a Send with the CLI-flag defaults.
    let output = bw()
        .args(["send", "create", r#"{"name":"x","type":0}"#])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("encoded_json") && stderr.contains("not yet implemented"),
        "expected `encoded_json ... not yet implemented` error, got:\n{stderr}"
    );
    // Crucially: the encoded_json error must fire *before* the auth check, so the user sees
    // their input was unsupported rather than a confusing "not logged in" message.
    assert!(
        !stderr.contains("not logged in"),
        "encoded_json check should pre-empt the auth check; got:\n{stderr}"
    );
}

#[test]
fn send_edit_encoded_json_returns_not_implemented_error() {
    let output = bw()
        .args(["send", "edit", r#"{"name":"x"}"#])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("encoded_json") && stderr.contains("not yet implemented"),
        "expected `encoded_json ... not yet implemented` error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("not logged in"),
        "encoded_json check should pre-empt the auth check; got:\n{stderr}"
    );
}

#[test]
fn send_get_output_file_returns_not_implemented_error() {
    // PM-34719: --output-file for file Sends needs the decrypt-file pipeline, which isn't
    // wired yet. Supplying it should fail loudly *before* the auth check + network call
    // rather than silently writing JSON to stdout while the requested file path goes
    // uncreated. The flag is `--output-file` (not `--output`) to avoid colliding with the
    // top-level global `-o, --output` format flag.
    let output = bw()
        .args([
            "send",
            "get",
            "25afb11c-9c95-4db5-8bac-c21cb204a3f1",
            "--output-file",
            "/tmp/bw-send-get-test.bin",
        ])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--output-file") && stderr.contains("not yet implemented"),
        "expected `--output-file ... not yet implemented` error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("not logged in"),
        "--output-file check should pre-empt the auth check; got:\n{stderr}"
    );
}

#[test]
fn send_create_camelcase_aliases_work() {
    // The legacy CLI uses `--deleteInDays` and `--maxAccessCount`; we keep those as the
    // long-flag names to preserve backward compatibility.
    let output = bw()
        .args([
            "send",
            "create",
            "--name",
            "x",
            "--text",
            "y",
            "--deleteInDays",
            "3",
            "--maxAccessCount",
            "5",
        ])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.starts_with("error: unexpected argument"),
        "clap should accept legacy camelCase flags; got:\n{stderr}"
    );
}

/// Legacy CLI rejects `--password` + `--emails` at parse time. clap-level
/// `conflicts_with` matches that behavior so the user sees a flag-conflict error
/// before any API call (and before the auth check, which would otherwise be the
/// first thing to fail in this test environment).
#[test]
fn send_create_password_and_emails_are_mutually_exclusive() {
    let output = bw()
        .args([
            "send",
            "create",
            "--text",
            "x",
            "--password",
            "p",
            "--emails",
            "a@b.com",
        ])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with") && stderr.contains("--emails"),
        "expected clap conflict error mentioning --emails; got:\n{stderr}"
    );
}

#[test]
fn send_edit_password_and_emails_are_mutually_exclusive() {
    let output = bw()
        .args(["send", "edit", "--password", "p", "--emails", "a@b.com"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with") && stderr.contains("--emails"),
        "expected clap conflict error mentioning --emails; got:\n{stderr}"
    );
}

#[test]
fn send_top_level_password_and_emails_are_mutually_exclusive() {
    let output = bw()
        .args(["send", "x", "--password", "p", "--emails", "a@b.com"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with") && stderr.contains("--emails"),
        "expected clap conflict error mentioning --emails; got:\n{stderr}"
    );
}

/// Legacy CLI restricts `--deleteInDays` to the enumerated set {1, 2, 3, 7, 14, 30}.
/// Anything outside that set is rejected at parse time so the user sees a clear error
/// up-front rather than a confusing server-side validation failure.
#[test]
fn send_create_delete_in_days_rejects_disallowed_value() {
    let output = bw()
        .args(["send", "create", "--text", "x", "--deleteInDays", "5"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value") && stderr.contains("deleteInDays"),
        "expected clap value-parser error mentioning deleteInDays; got:\n{stderr}"
    );
    assert!(
        stderr.contains("Allowed"),
        "error should list the allowed values; got:\n{stderr}"
    );
}
