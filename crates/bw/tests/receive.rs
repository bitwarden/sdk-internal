//! Integration tests for `bw receive` / `bw send receive`.
//!
//! Unlike the rest of the Send commands, `receive` needs no session, so the whole flow — token
//! negotiation against identity, fetching the send, decrypting with the key from the URL
//! fragment, and saving a file send — can be driven end-to-end here against a `wiremock`
//! server. The receive URL points at the mock server, and `resolve_urls`' self-host fallback
//! turns that origin into `<origin>/api` + `<origin>/identity`, which is what the mocks serve.
//!
//! The ciphertext in these tests is produced with `bitwarden-crypto` directly from a known
//! 16-byte key, so a test failure means the CLI's derivation diverged from
//! `derive_shareable_key(key, "send", Some("send"))` — the same derivation `bw send create` uses.
//!
//! Each [`run_bw`] call scopes the CLI's appdata to a fresh tempdir (see [`TempAppdata`]), so the
//! suite never touches the developer's real appdata directory, or leaks a cached send-access
//! token between tests — same convention as `config.rs`.

use std::process::Stdio;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bitwarden_crypto::{
    KeyEncryptable as _, OctetStreamBytes, SymmetricCryptoKey, derive_shareable_key,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};
use zeroize::Zeroizing;

mod common;
use common::bw;

/// The raw send key that a real Send URL fragment would carry, url-safe-base64 encoded.
const KEY_BYTES: [u8; 16] = *b"0123456789abcdef";
const SEND_ID: &str = "access-id";
const FILE_ID: &str = "file-id";
const ACCESS_TOKEN: &str = "send-access-token";

fn send_key() -> SymmetricCryptoKey {
    SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
        Zeroizing::new(KEY_BYTES),
        "send",
        Some("send"),
    ))
}

fn url_key() -> String {
    URL_SAFE_NO_PAD.encode(KEY_BYTES)
}

fn encrypt_string(value: &str) -> String {
    value
        .to_string()
        .encrypt_with_key(&send_key())
        .expect("string encrypts")
        .to_string()
}

/// Encrypt a file blob the way `create_file_send` uploads it: one whole-buffer `EncString`.
fn encrypt_buffer(data: &[u8]) -> Vec<u8> {
    (&OctetStreamBytes::from(data.to_vec()))
        .encrypt_with_key(&send_key())
        .expect("buffer encrypts")
        .to_buffer()
        .expect("buffer serializes")
}

/// The receive URL for a mock server, in the web-vault `#/send/<id>/<key>` shape.
fn receive_url(server: &MockServer) -> String {
    format!("{}/#/send/{}/{}", server.uri(), SEND_ID, url_key())
}

fn token_success() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": "api.send.access",
    }))
}

/// A 400 from the token endpoint carrying one of identity's typed `send_access_error_type`s.
fn token_error(error: &str, error_type: &str) -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(serde_json::json!({
        "error": error,
        "send_access_error_type": error_type,
    }))
}

async fn mock_token(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(response)
        .mount(server)
        .await;
}

/// A fresh, unique appdata directory for one `bw` invocation, so `resolve_urls`'s config lookup
/// and the send-access-token cache never touch the developer's real
/// `~/Library/Application Support/Bitwarden CLI` (or another test's directory) — mirrors
/// `config.rs`'s `TempAppdata` pattern. Removed on drop.
struct TempAppdata(std::path::PathBuf);

impl TempAppdata {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "bw-receive-it-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4(),
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        Self(dir)
    }

    /// Writes a `config.json` naming `server` as the configured deployment, so `resolve_urls`
    /// treats a matching-origin Send link as trusted (mirrors `bw config server <server>`).
    fn configure_server(&self, server: &str) {
        std::fs::write(
            self.0.join("config.json"),
            serde_json::json!({ "server": server }).to_string(),
        )
        .expect("write config.json");
    }
}

impl Drop for TempAppdata {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the CLI without a session and with stdin closed, so a regression that reaches an
/// interactive prompt fails the test instead of hanging it. Each call gets its own fresh
/// [`TempAppdata`] — callers that need the *same* appdata directory across multiple invocations
/// (e.g. to exercise the send-access-token cache) should use [`run_bw_in`] instead.
async fn run_bw(args: Vec<String>, envs: Vec<(&str, &str)>) -> std::process::Output {
    let appdata = TempAppdata::new();
    run_bw_in(&appdata, args, envs).await
}

/// Like [`run_bw`], but against a caller-supplied appdata directory, so a test can make two
/// invocations share state (e.g. a warm send-access-token cache).
async fn run_bw_in(
    appdata: &TempAppdata,
    args: Vec<String>,
    envs: Vec<(&str, &str)>,
) -> std::process::Output {
    let mut command = bw();
    command
        .args(args)
        .stdin(Stdio::null())
        .env_remove("BW_EMAIL")
        .env_remove("BW_PASSWORD")
        .env_remove("BW_NOINTERACTION")
        .env("BITWARDENCLI_APPDATA_DIR", &appdata.0);
    for (key, value) in envs {
        command.env(key, value);
    }
    tokio::task::spawn_blocking(move || command.output().expect("Failed to execute bw"))
        .await
        .expect("bw subprocess joins")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

// ===== Help / arg surface =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_help_advertises_every_password_source() {
    // `bw receive` and `bw send receive` are the same command under two names; both must
    // advertise the full flag set.
    for args in [
        vec!["receive".to_string(), "--help".to_string()],
        vec![
            "send".to_string(),
            "receive".to_string(),
            "--help".to_string(),
        ],
    ] {
        let output = run_bw(args.clone(), vec![]).await;
        assert!(output.status.success(), "`bw {args:?}` should succeed");
        let stdout = stdout(&output);
        for flag in ["--password", "--passwordenv", "--passwordfile", "--output"] {
            assert!(
                stdout.contains(flag),
                "`bw {args:?}` should advertise {flag}; got:\n{stdout}"
            );
        }
        assert!(
            stdout.contains("--fullObject"),
            "`bw {args:?}` should advertise --fullObject; got:\n{stdout}"
        );
        assert!(
            stdout.contains("the user is prompted"),
            "`bw {args:?}` should document the password prompt; got:\n{stdout}"
        );
    }
}

// ===== URL validation (no server required) =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_rejects_a_malformed_url_without_needing_auth() {
    let output = run_bw(vec!["receive".to_string(), "not-a-url".to_string()], vec![]).await;
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("Failed to parse the provided Send url"),
        "expected the url parse error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("not logged in"),
        "receive must never require a session; got:\n{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_rejects_a_url_without_a_send_fragment() {
    let output = run_bw(
        vec![
            "receive".to_string(),
            "https://vault.bitwarden.com/".to_string(),
        ],
        vec![],
    )
    .await;
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not a valid Send url"),
        "got:\n{}",
        stderr(&output)
    );
}

/// A fragment whose trailing segment isn't a 16-byte url-safe-base64 key can't be a Send link;
/// it must be rejected locally rather than sending a request anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_rejects_a_fragment_key_that_is_not_a_send_key() {
    let output = run_bw(
        vec![
            "receive".to_string(),
            "https://vault.bitwarden.com/#/send/access-id/too-short".to_string(),
        ],
        vec![],
    )
    .await;
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not a valid Send url"),
        "got:\n{}",
        stderr(&output)
    );
}

// ===== End-to-end: text sends =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_prints_a_text_sends_content() {
    let server = MockServer::start().await;
    mock_token(&server, token_success()).await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 0,
            "name": encrypt_string("My Send"),
            "text": { "text": encrypt_string("the secret text"), "hidden": false },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = run_bw(vec!["receive".to_string(), receive_url(&server)], vec![]).await;

    assert!(
        output.status.success(),
        "receive should succeed; stderr:\n{}",
        stderr(&output)
    );
    assert_eq!(stdout(&output).trim_end(), "the secret text");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_full_object_emits_the_decrypted_json() {
    let server = MockServer::start().await;
    mock_token(&server, token_success()).await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 0,
            "name": encrypt_string("My Send"),
            "text": { "text": encrypt_string("the secret text"), "hidden": true },
            "creatorIdentifier": "owner@example.com",
        })))
        .mount(&server)
        .await;

    let output = run_bw(
        vec![
            "receive".to_string(),
            receive_url(&server),
            "--fullObject".to_string(),
        ],
        vec![],
    )
    .await;

    assert!(output.status.success(), "stderr:\n{}", stderr(&output));
    let stdout = stdout(&output);
    // The decrypted name and text both surface, in the legacy camelCase shape.
    assert!(stdout.contains("\"name\""), "got:\n{stdout}");
    assert!(stdout.contains("My Send"), "got:\n{stdout}");
    assert!(stdout.contains("the secret text"), "got:\n{stdout}");
    assert!(stdout.contains("creatorIdentifier"), "got:\n{stdout}");
}

/// `--full-object` is accepted as an alias so the flag is reachable without shell-quoting a
/// camelCase name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_accepts_the_kebab_case_full_object_alias() {
    let server = MockServer::start().await;
    mock_token(&server, token_success()).await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 0,
            "name": encrypt_string("My Send"),
            "text": { "text": encrypt_string("the secret text"), "hidden": false },
        })))
        .mount(&server)
        .await;

    let output = run_bw(
        vec![
            "receive".to_string(),
            receive_url(&server),
            "--full-object".to_string(),
        ],
        vec![],
    )
    .await;

    assert!(output.status.success(), "stderr:\n{}", stderr(&output));
    assert!(stdout(&output).contains("My Send"));
}

/// `bw send receive` must behave identically to `bw receive`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_receive_alias_runs_the_same_flow() {
    let server = MockServer::start().await;
    mock_token(&server, token_success()).await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 0,
            "name": encrypt_string("My Send"),
            "text": { "text": encrypt_string("via the alias"), "hidden": false },
        })))
        .mount(&server)
        .await;

    let output = run_bw(
        vec![
            "send".to_string(),
            "receive".to_string(),
            receive_url(&server),
        ],
        vec![],
    )
    .await;

    assert!(output.status.success(), "stderr:\n{}", stderr(&output));
    assert_eq!(stdout(&output).trim_end(), "via the alias");
}

// ===== End-to-end: password-protected sends =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_exchanges_a_supplied_password_for_a_token() {
    let server = MockServer::start().await;
    // First (anonymous) attempt: the server says a password hash is required. Mounted first and
    // capped at one call, so the credentialed retry falls through to the success mock below.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(token_error("invalid_request", "password_hash_b64_required"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Second attempt: must carry the derived password hash.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("password_hash_b64"))
        .respond_with(token_success())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 0,
            "name": encrypt_string("Protected"),
            "text": { "text": encrypt_string("password gated"), "hidden": false },
        })))
        .mount(&server)
        .await;

    let output = run_bw(
        vec![
            "receive".to_string(),
            receive_url(&server),
            "--password".to_string(),
            "hunter2".to_string(),
        ],
        vec![],
    )
    .await;

    assert!(output.status.success(), "stderr:\n{}", stderr(&output));
    assert_eq!(stdout(&output).trim_end(), "password gated");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_reads_the_password_from_an_environment_variable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(token_error("invalid_request", "password_hash_b64_required"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("password_hash_b64"))
        .respond_with(token_success())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 0,
            "name": encrypt_string("Protected"),
            "text": { "text": encrypt_string("from the env"), "hidden": false },
        })))
        .mount(&server)
        .await;

    let output = run_bw(
        vec![
            "receive".to_string(),
            receive_url(&server),
            "--passwordenv".to_string(),
            "BW_TEST_SEND_PASSWORD".to_string(),
        ],
        vec![("BW_TEST_SEND_PASSWORD", "hunter2")],
    )
    .await;

    assert!(output.status.success(), "stderr:\n{}", stderr(&output));
    assert_eq!(stdout(&output).trim_end(), "from the env");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_reports_an_invalid_password() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(token_error("invalid_request", "password_hash_b64_required"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("password_hash_b64"))
        .respond_with(token_error("invalid_grant", "password_hash_b64_invalid"))
        .mount(&server)
        .await;

    let output = run_bw(
        vec![
            "receive".to_string(),
            receive_url(&server),
            "--password".to_string(),
            "wrong".to_string(),
        ],
        vec![],
    )
    .await;

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("Invalid password"),
        "got:\n{}",
        stderr(&output)
    );
}

/// With `BW_NOINTERACTION=true` a password-protected Send must fail fast instead of blocking on
/// a prompt that can never be answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_errors_instead_of_prompting_when_non_interactive() {
    let server = MockServer::start().await;
    mock_token(
        &server,
        token_error("invalid_request", "password_hash_b64_required"),
    )
    .await;

    let output = run_bw(
        vec!["receive".to_string(), receive_url(&server)],
        vec![("BW_NOINTERACTION", "true")],
    )
    .await;

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("Password required"),
        "got:\n{}",
        stderr(&output)
    );
}

/// Email-OTP Sends can't be completed without a prompt, so the non-interactive path must say so
/// rather than failing with a generic server error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_reports_that_email_verification_needs_interactive_mode() {
    let server = MockServer::start().await;
    mock_token(&server, token_error("invalid_request", "email_required")).await;

    let output = run_bw(
        vec!["receive".to_string(), receive_url(&server)],
        vec![("BW_NOINTERACTION", "true")],
    )
    .await;

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("Email verification required"),
        "got:\n{}",
        stderr(&output)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_reports_an_unknown_send_as_not_found() {
    let server = MockServer::start().await;
    mock_token(&server, token_error("invalid_grant", "send_id_invalid")).await;

    let output = run_bw(vec!["receive".to_string(), receive_url(&server)], vec![]).await;

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("Not found"),
        "got:\n{}",
        stderr(&output)
    );
}

// ===== End-to-end: file sends =====

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_downloads_decrypts_and_saves_a_file_send() {
    let contents = b"the file contents";
    let server = MockServer::start().await;
    mock_token(&server, token_success()).await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 1,
            "name": encrypt_string("File Send"),
            "file": {
                "id": FILE_ID,
                "fileName": encrypt_string("secrets.txt"),
                "size": "17",
                "sizeName": "17 B",
            },
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/sends/access/file/{FILE_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-fileDownload",
            "id": FILE_ID,
            "url": format!("{}/blob", server.uri()),
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/blob"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(encrypt_buffer(contents)))
        .expect(1)
        .mount(&server)
        .await;

    // `--output <dir>/` (trailing separator) makes the Send's own decrypted file name the
    // target, which is the branch most likely to break.
    let dir = std::env::temp_dir().join(format!(
        "bw-receive-file-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let output_path = format!("{}{}", dir.display(), std::path::MAIN_SEPARATOR);

    let output = run_bw(
        vec![
            "receive".to_string(),
            receive_url(&server),
            "--output".to_string(),
            output_path,
        ],
        vec![],
    )
    .await;

    assert!(output.status.success(), "stderr:\n{}", stderr(&output));
    let saved = dir.join("secrets.txt");
    assert!(
        stdout(&output).contains(&format!("Saved {}", saved.display())),
        "expected the saved path on stdout, got:\n{}",
        stdout(&output)
    );
    assert_eq!(
        std::fs::read(&saved).expect("the decrypted file exists"),
        contents
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A non-2xx from the blob storage URL must surface legacy's download error rather than writing
/// a truncated or empty file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_reports_a_failed_file_download() {
    let server = MockServer::start().await;
    mock_token(&server, token_success()).await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 1,
            "name": encrypt_string("File Send"),
            "file": {
                "id": FILE_ID,
                "fileName": encrypt_string("secrets.txt"),
                "size": "17",
                "sizeName": "17 B",
            },
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/sends/access/file/{FILE_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-fileDownload",
            "id": FILE_ID,
            "url": format!("{}/blob", server.uri()),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/blob"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let output = run_bw(vec!["receive".to_string(), receive_url(&server)], vec![]).await;

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("404") && stderr(&output).contains("downloading the attachment"),
        "got:\n{}",
        stderr(&output)
    );
}

// ===== Send-access token cache =====

/// A second `bw receive` for the same send, within the same appdata directory, must not mint a
/// second token — the cache from the first call should be reused. The token mock is capped at
/// `expect(1)`: a second call to it fails the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_reuses_a_cached_token_on_a_second_invocation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(token_success())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 0,
            "name": encrypt_string("My Send"),
            "text": { "text": encrypt_string("the secret text"), "hidden": false },
        })))
        .expect(2)
        .mount(&server)
        .await;

    // A wiremock server's origin is neither a known cloud host nor (without this) a configured
    // deployment, so it would otherwise be untrusted and never cached — configure it as the
    // deployment so this test exercises the trusted, cached path.
    let appdata = TempAppdata::new();
    appdata.configure_server(&server.uri());
    let first = run_bw_in(
        &appdata,
        vec!["receive".to_string(), receive_url(&server)],
        vec![],
    )
    .await;
    assert!(
        first.status.success(),
        "first receive should succeed; stderr:\n{}",
        stderr(&first)
    );
    assert_eq!(stdout(&first).trim_end(), "the secret text");

    let second = run_bw_in(
        &appdata,
        vec!["receive".to_string(), receive_url(&server)],
        vec![],
    )
    .await;
    assert!(
        second.status.success(),
        "second receive should succeed from the cached token; stderr:\n{}",
        stderr(&second)
    );
    assert_eq!(stdout(&second).trim_end(), "the secret text");

    // wiremock verifies the `expect(1)`/`expect(2)` bounds when `server` drops at end of scope.
}

/// An untrusted host (neither a known cloud host nor the configured deployment — a bare
/// wiremock server, unconfigured, is exactly this case) must never get a persistent cache entry
/// at all, matching the corresponding TS client fix. The token mock is capped at `expect(2)`:
/// caching would make a second call to it fail this test the same way a missing second call
/// would fail the cached-token test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_does_not_cache_a_token_for_an_untrusted_host() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(token_success())
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/sends/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "send-access",
            "id": SEND_ID,
            "type": 0,
            "name": encrypt_string("My Send"),
            "text": { "text": encrypt_string("the secret text"), "hidden": false },
        })))
        .expect(2)
        .mount(&server)
        .await;

    // Deliberately no `configure_server` call: this host stays untrusted.
    let appdata = TempAppdata::new();
    let first = run_bw_in(
        &appdata,
        vec!["receive".to_string(), receive_url(&server)],
        vec![],
    )
    .await;
    assert!(
        first.status.success(),
        "first receive should succeed; stderr:\n{}",
        stderr(&first)
    );

    let second = run_bw_in(
        &appdata,
        vec!["receive".to_string(), receive_url(&server)],
        vec![],
    )
    .await;
    assert!(
        second.status.success(),
        "second receive should succeed by minting a fresh token; stderr:\n{}",
        stderr(&second)
    );

    // wiremock verifies the `expect(2)` bounds when `server` drops at end of scope.
}
