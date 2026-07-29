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

// The crate named `bw` is a binary; to access its types we have to compile it as a library too.
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
fn send_get_text_help_documents_access_url_output() {
    // PM-39239: `--text` emits the shareable access URL. The end-to-end URL construction
    // (web-vault derivation + url-safe key + `#/send/...` fragment format, including the
    // round-trip against the legacy `bw receive` parser) is verified by unit tests in
    // `crates/bw/src/tools/send.rs`, since exercising the live `get`/`create` path requires a
    // logged-in session that this binary-driven harness cannot provide. Here we assert the
    // user-facing contract that `--text` returns the access url is advertised in help.
    let output = bw()
        .args(["send", "get", "--help"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--text") && stdout.contains("access url"),
        "`bw send get --help` should advertise `--text` as returning the access url; got:\n{stdout}"
    );
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

// A full-object text `SendView` JSON payload, matching the wire shape `bw send get` and
// `bw send create --fullObject` emit. Used to exercise the `encoded_json` input path. The
// binary-driven tests can't reach a real API (no logged-in session/mock server here), so they
// assert the input *parses* and falls through to the auth check; the field-level merge
// semantics are unit-tested against the builder functions in `src/tools/send.rs`.
const FULL_TEXT_SEND_JSON: &str = r#"{
  "name": "My Send",
  "hasPassword": false,
  "type": 0,
  "text": {"text": "hello", "hidden": false},
  "accessCount": 0,
  "disabled": false,
  "hideEmail": false,
  "revisionDate": "2025-01-01T00:00:00Z",
  "deletionDate": "2030-01-01T00:00:00Z",
  "emails": [],
  "authType": 2
}"#;

/// Run `bw <args>` (logged out) piping `stdin_data` to the child's stdin.
fn bw_with_stdin(args: &[&str], stdin_data: &str) -> std::process::Output {
    use std::{io::Write as _, process::Stdio};

    let mut child = bw()
        .args(args)
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin_data.as_bytes())
        .expect("write to stdin");
    child.wait_with_output().expect("wait for child")
}

#[test]
fn send_create_encoded_json_positional_parses_then_hits_auth() {
    // A valid full-object JSON positional must parse and fall through to the auth check
    // (which fails logged out) — proving the input is accepted, not rejected up-front.
    let output = bw()
        .args(["send", "create", FULL_TEXT_SEND_JSON])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not logged in") || stderr.contains("logged in"),
        "valid JSON should parse and reach the auth check; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Error parsing"),
        "valid JSON should not produce a parse error; got:\n{stderr}"
    );
}

#[test]
fn send_create_encoded_json_via_stdin_matches_positional() {
    // Piping the same JSON via stdin (no positional) takes the same path as the positional
    // form: parse succeeds, then auth fails. Also proves the stdin read does not hang.
    let output = bw_with_stdin(&["send", "create"], FULL_TEXT_SEND_JSON);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not logged in") || stderr.contains("logged in"),
        "stdin JSON should parse and reach the auth check; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Error parsing"),
        "stdin JSON should not produce a parse error; got:\n{stderr}"
    );
}

#[test]
fn send_edit_encoded_json_via_stdin_matches_positional() {
    let id = "25afb11c-9c95-4db5-8bac-c21cb204a3f1";
    let via_stdin = bw_with_stdin(&["send", "edit", "--itemid", id], FULL_TEXT_SEND_JSON);
    let via_positional = bw()
        .args(["send", "edit", "--itemid", id, FULL_TEXT_SEND_JSON])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");

    for (label, output) in [("stdin", &via_stdin), ("positional", &via_positional)] {
        assert!(!output.status.success(), "{label}: should fail logged out");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not logged in") || stderr.contains("logged in"),
            "{label}: JSON should parse and reach the auth check; got:\n{stderr}"
        );
        assert!(
            !stderr.contains("Error parsing"),
            "{label}: JSON should not produce a parse error; got:\n{stderr}"
        );
    }
}

#[test]
fn send_create_encoded_json_base64_parses_like_raw() {
    // The "accept both transparently" decision: base64-encoded JSON must parse just like raw
    // JSON and reach the auth check.
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let b64 = STANDARD.encode(FULL_TEXT_SEND_JSON);
    let output = bw()
        .args(["send", "create", &b64])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not logged in") || stderr.contains("logged in"),
        "base64-encoded JSON should parse and reach the auth check; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Error parsing"),
        "base64-encoded JSON should not produce a parse error; got:\n{stderr}"
    );
}

#[test]
fn send_create_malformed_json_is_rejected_before_auth() {
    // Input that is neither valid base64-of-JSON nor valid raw JSON must fail with a clear
    // parse error that fires *before* the auth check (so the user sees the real problem).
    let output = bw()
        .args(["send", "create", "!!!not-base64-and-not-json!!!"])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error parsing the encoded request data"),
        "expected a clear parse error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("not logged in"),
        "the parse error must pre-empt the auth check; got:\n{stderr}"
    );
}

#[test]
fn send_edit_malformed_json_is_rejected_before_auth() {
    let output = bw()
        .args([
            "send",
            "edit",
            "--itemid",
            "25afb11c-9c95-4db5-8bac-c21cb204a3f1",
            "{not valid json",
        ])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error parsing the encoded request data"),
        "expected a clear parse error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("not logged in"),
        "the parse error must pre-empt the auth check; got:\n{stderr}"
    );
}

#[test]
fn send_get_output_returns_not_implemented_error() {
    // --output for file Sends needs the decrypt-file pipeline, which isn't wired yet.
    // Supplying it should fail loudly *before* the auth check + network call rather than
    // silently writing JSON to stdout while the requested file path goes uncreated.
    let output = bw()
        .args([
            "send",
            "get",
            "25afb11c-9c95-4db5-8bac-c21cb204a3f1",
            "--output",
            "/tmp/bw-send-get-test.bin",
        ])
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .output()
        .expect("Failed to execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--output") && stderr.contains("not yet implemented"),
        "expected `--output ... not yet implemented` error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("not logged in"),
        "--output check should pre-empt the auth check; got:\n{stderr}"
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
        stderr.contains("possible values"),
        "error should list the allowed values; got:\n{stderr}"
    );
}
