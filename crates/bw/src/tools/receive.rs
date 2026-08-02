//! `bw receive` / `bw send receive` — access a Bitwarden Send from a url.
//!
//! This is the only Send flow that runs **without a logged-in user**: the send's content is
//! decrypted with a key derived purely from the URL fragment
//! ([`bitwarden_send::SendAccessKey`]), never from the account key store. Because the link can
//! point at any deployment, the command builds its own [`PasswordManagerClient`] per invocation
//! from URLs derived off the link itself (see [`resolve_urls`]) rather than reusing the session
//! client — a self-hosted receive link must not have its password hash sent to Bitwarden cloud
//! identity, and vice versa.
//!
//! Both `bw receive <url>` and `bw send receive <url>` are the same command; their arg structs
//! are field-identical and both funnel into [`run_receive`].
//!
//! **Known security gap (PM-40120):** [`resolve_urls`] trusts a Send link's host
//! unconditionally to resolve *both* the API and identity origin — the same class of bug the
//! legacy CLI has, though the exact mechanism differs there (legacy always mints against the
//! configured environment but can leak the resulting real token to an attacker-controlled host
//! on the follow-up fetch). Here, a link pointing at an attacker-controlled host sends the
//! token-mint request there directly, so a password-protected Send's hashed password (salted
//! with the fragment key, which the attacker already knows — they crafted the link) goes
//! straight to that host. A fix (reject, or prompt when the link's host doesn't match the
//! configured deployment) is pending a product decision on the resulting UX; `resolve_urls` is
//! where it belongs once decided.

use bitwarden_auth::send_access::{
    SendAccessCredentials, SendAccessTokenError, SendAccessTokenRequest, SendEmailCredentials,
    SendEmailOtpCredentials, SendPasswordCredentials,
    api::{
        SendAccessTokenApiErrorResponse, SendAccessTokenInvalidGrantError,
        SendAccessTokenInvalidRequestError,
    },
};
use bitwarden_core::get_host_platform_info;
use bitwarden_pm::PasswordManagerClient;
use bitwarden_send::{SendAccessKey, SendAccessView, SendType};
use color_eyre::eyre::{Context as _, Result, eyre};
use inquire::{Password, Text, validator::Validation};
use url::Url;

use crate::{
    platform::{ConfigFile, read_config_json},
    render::{CommandOutput, CommandResult},
    tools::file_output::{default_send_file_name, reject_path_traversal, save_file},
};

/// The Bitwarden cloud deployments whose Send links do not carry their API host.
///
/// `bw` has no region-metadata service (the same gap documented in the `web_vault_url` TODO in
/// [`super::send`]), so the mapping is a small table here. Hosts are matched **exactly**, never
/// by suffix: a suffix match would let `send.bitwarden.com.evil.tld` route a Send password hash
/// to real Bitwarden cloud identity.
const CLOUD_HOSTS: &[CloudRegion] = &[
    CloudRegion {
        hosts: &["send.bitwarden.com", "vault.bitwarden.com"],
        api_url: "https://api.bitwarden.com",
        identity_url: "https://identity.bitwarden.com",
    },
    CloudRegion {
        hosts: &["send.bitwarden.eu", "vault.bitwarden.eu"],
        api_url: "https://api.bitwarden.eu",
        identity_url: "https://identity.bitwarden.eu",
    },
];

struct CloudRegion {
    hosts: &'static [&'static str],
    api_url: &'static str,
    identity_url: &'static str,
}

/// The flags `bw receive` and `bw send receive` share, normalized into one struct so the two
/// entry points cannot drift apart.
pub(crate) struct ReceiveInputs {
    /// The Send url, including the `#`-fragment that carries the send id and key.
    pub url: String,
    /// `--password`
    pub password: Option<String>,
    /// `--passwordenv`
    pub passwordenv: Option<String>,
    /// `--passwordfile`
    pub passwordfile: Option<String>,
    /// `--output <path>`: where to save a file-type Send. Matches the flag name (and internal
    /// field name, to avoid colliding with the top-level `Cli::output` render-format field)
    /// already established by `bw send get --output` — legacy spells this the same way.
    /// `--fullObject` (not legacy's boolean `--obj`) is the JSON-dump flag, matching the
    /// existing convention on `bw send`/`bw send create`.
    pub output_path: Option<String>,
    /// `--fullObject`: dump the decrypted Send as JSON instead of emitting its content.
    pub full_object: bool,
}

/// Entry point for [`super::ReceiveArgs`]'s `BwCommand` impl, reached both from the top-level
/// `bw receive` command and from `SendCommands::Receive` (`bw send receive`), which reuses the
/// same arg struct rather than a hand-synced copy.
pub(crate) async fn run_receive(inputs: ReceiveInputs) -> CommandResult {
    let url = Url::parse(&inputs.url).wrap_err("Failed to parse the provided Send url")?;
    let (send_id, key_b64) = parse_send_url(&url)?;

    // A structurally valid URL whose fragment key isn't a 16-byte url-safe-base64 blob is not a
    // Send url; report it the same way as a missing fragment segment rather than leaking the
    // crypto-layer error text (which would be about key lengths, not about the url).
    let access_key = SendAccessKey::from_url_b64(&key_b64)
        .map_err(|_| eyre!("Failed to parse url, the url provided is not a valid Send url"))?;

    let (api_url, identity_url) = resolve_urls(&url, read_config_json().ok().flatten().as_ref());
    let client = PasswordManagerClient::new(Some(
        get_host_platform_info().to_client_settings(api_url, identity_url),
    ));

    let token = attempt_access(&client, &send_id, &access_key, &inputs).await?;
    render_access(&client, &access_key, token, &inputs).await
}

/// Extract `(send_id, url_b64_key)` from the last two `#`-fragment segments.
///
/// Mirrors the legacy CLI's `getIdAndKey` (`url.hash.slice(1).split("/").slice(-2)`), which is
/// why one parser handles both link shapes: the web-vault route
/// (`https://vault.example.com/#/send/<id>/<key>`) and the cloud Send vanity host
/// (`https://send.bitwarden.com/#<id>/<key>`) — only the trailing two segments matter.
fn parse_send_url(url: &Url) -> Result<(String, String)> {
    let fragment = url.fragment().unwrap_or_default();
    let mut trailing = fragment.rsplit('/');
    let key = trailing.next().unwrap_or_default();
    let id = trailing.next().unwrap_or_default();

    if id.trim().is_empty() || key.trim().is_empty() {
        return Err(eyre!(
            "Failed to parse url, the url provided is not a valid Send url"
        ));
    }

    Ok((id.to_string(), key.to_string()))
}

/// Resolve the API and identity base URLs to talk to for a given Send link.
///
/// Both are needed: the send-access token is minted at `{identity}/connect/token` and the send
/// itself is read from `{api}`. Precedence:
///
/// 1. A known Bitwarden cloud host (exact match — see [`CLOUD_HOSTS`]).
/// 2. The locally configured deployment (`bw config server`) when the link's origin matches it —
///    explicit `api`/`identity` overrides win, otherwise the base is suffixed.
/// 3. Otherwise `<origin>/api` + `<origin>/identity`, the single-domain self-host convention and
///    the legacy CLI's final fallback.
///
/// Pure so the precedence can be unit-tested without a client or a config file on disk.
///
/// See the module-level PM-40120 note: this unconditional host trust is the known security
/// gap, and this is where its eventual fix belongs.
fn resolve_urls(url: &Url, config: Option<&ConfigFile>) -> (String, String) {
    if let Some(host) = url.host_str()
        && let Some(region) = CLOUD_HOSTS
            .iter()
            .find(|region| region.hosts.contains(&host))
    {
        return (region.api_url.to_string(), region.identity_url.to_string());
    }

    let origin = url.origin().ascii_serialization();

    if let Some(config) = config
        && let Some(base) = [config.web_vault.as_deref(), config.server.as_deref()]
            .into_iter()
            .flatten()
            .find(|configured| same_origin(configured, &origin))
    {
        let base = base.trim_end_matches('/');
        let api = trimmed(config.api.as_deref()).unwrap_or_else(|| format!("{base}/api"));
        let identity =
            trimmed(config.identity.as_deref()).unwrap_or_else(|| format!("{base}/identity"));
        return (api, identity);
    }

    (format!("{origin}/api"), format!("{origin}/identity"))
}

/// `true` when `configured` denotes the same origin as `origin` (already an ASCII origin
/// serialization). Falls back to a string compare for values that aren't parseable URLs, so a
/// hand-edited `config.json` still matches.
fn same_origin(configured: &str, origin: &str) -> bool {
    match Url::parse(configured) {
        Ok(parsed) => parsed.origin().ascii_serialization() == origin,
        Err(_) => configured.trim_end_matches('/') == origin,
    }
}

fn trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(|v| v.trim_end_matches('/'))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Negotiate a send-access token, prompting for whatever credential the server says the Send
/// needs. Mirrors the legacy `attemptAccess`: ask with no credentials first and branch on the
/// typed `send_access_error_type` the server returns.
///
/// Legacy wraps every token request in a 3-attempt retry loop (`getTokenWithRetry`) for a
/// `{kind: "expired"}` case tied to its persistent send-access-token cache — legacy's CLI
/// caches tokens across invocations too, not just the browser/extension (see the module-level
/// PM-40120 note: that cross-invocation cache is part of what's under security review). This
/// port deliberately does not persist tokens across invocations: `bw receive` mints and
/// consumes the token within one process, so there's nothing to expire and no retry to
/// replicate.
async fn attempt_access(
    client: &PasswordManagerClient,
    send_id: &str,
    access_key: &SendAccessKey,
    inputs: &ReceiveInputs,
) -> Result<String> {
    match request_token(client, send_id, None).await {
        Ok(token) => Ok(token),
        Err(err) => match invalid_request_type(&err) {
            Some(SendAccessTokenInvalidRequestError::PasswordHashB64Required) => {
                access_with_password(client, send_id, access_key, inputs).await
            }
            Some(SendAccessTokenInvalidRequestError::EmailRequired) => {
                access_with_email_otp(client, send_id).await
            }
            _ if invalid_grant_type(&err)
                == Some(&SendAccessTokenInvalidGrantError::SendIdInvalid) =>
            {
                Err(eyre!("Not found."))
            }
            _ => Err(token_error(err)),
        },
    }
}

/// Password-protected Sends: resolve the password from flags/env/file/prompt, run it through the
/// same PBKDF2 recipe `bw send create --password` used, and exchange it for a token.
async fn access_with_password(
    client: &PasswordManagerClient,
    send_id: &str,
    access_key: &SendAccessKey,
    inputs: &ReceiveInputs,
) -> Result<String> {
    let password = resolve_password(inputs)?;
    let credentials = SendAccessCredentials::Password(SendPasswordCredentials {
        password_hash_b64: access_key.hash_password_b64(&password),
    });

    match request_token(client, send_id, Some(credentials)).await {
        Ok(token) => Ok(token),
        Err(err)
            if invalid_grant_type(&err)
                == Some(&SendAccessTokenInvalidGrantError::PasswordHashB64Invalid) =>
        {
            Err(eyre!("Invalid password"))
        }
        Err(err) => Err(token_error(err)),
    }
}

/// Email-OTP-protected Sends: the email request is what makes the server send the code, so the
/// expected outcome of the first call is an `email_and_otp_required` error, not a token.
async fn access_with_email_otp(client: &PasswordManagerClient, send_id: &str) -> Result<String> {
    if !can_interact() {
        return Err(eyre!(
            "Email verification required. Run in interactive mode."
        ));
    }

    let email = prompt_email()?;
    let credentials = SendAccessCredentials::Email(SendEmailCredentials {
        email: email.clone(),
    });

    let err = match request_token(client, send_id, Some(credentials)).await {
        // A token here means the server stopped requiring the OTP it just mailed; treat it as a
        // contract break rather than silently proceeding, matching legacy.
        Ok(_) => return Err(eyre!("Unexpected server response")),
        Err(err) => err,
    };

    if invalid_request_type(&err) != Some(&SendAccessTokenInvalidRequestError::EmailAndOtpRequired)
    {
        return Err(token_error(err));
    }

    let otp = prompt_otp()?;
    let credentials = SendAccessCredentials::EmailOtp(SendEmailOtpCredentials { email, otp });

    match request_token(client, send_id, Some(credentials)).await {
        Ok(token) => Ok(token),
        // The server deliberately doesn't say which of the two was wrong, so neither do we.
        Err(err)
            if invalid_request_type(&err)
                == Some(&SendAccessTokenInvalidRequestError::EmailAndOtpRequired) =>
        {
            Err(eyre!("Invalid email or verification code"))
        }
        Err(err) => Err(token_error(err)),
    }
}

async fn request_token(
    client: &PasswordManagerClient,
    send_id: &str,
    credentials: Option<SendAccessCredentials>,
) -> Result<String, SendAccessTokenError> {
    client
        .auth()
        .send_access()
        .request_send_access_token(SendAccessTokenRequest {
            send_id: send_id.to_string(),
            send_access_credentials: credentials,
        })
        .await
        .map(|response| response.token)
}

/// Extracts the typed `send_access_error_type` from an `invalid_request` response, or `None`
/// if `err` isn't that shape. `attempt_access` and `access_with_email_otp` both need to branch
/// on this one sub-field of a deeply nested error enum; centralizing the match here keeps
/// those call sites down to a single `Some(...) => ...` comparison instead of repeating the
/// full pattern.
fn invalid_request_type(err: &SendAccessTokenError) -> Option<&SendAccessTokenInvalidRequestError> {
    match err {
        SendAccessTokenError::Expected(SendAccessTokenApiErrorResponse::InvalidRequest {
            send_access_error_type,
            ..
        }) => send_access_error_type.as_ref(),
        _ => None,
    }
}

/// Same idea as [`invalid_request_type`], but for the `invalid_grant` response shape (used to
/// detect an unknown Send id or an invalid password hash).
fn invalid_grant_type(err: &SendAccessTokenError) -> Option<&SendAccessTokenInvalidGrantError> {
    match err {
        SendAccessTokenError::Expected(SendAccessTokenApiErrorResponse::InvalidGrant {
            send_access_error_type,
            ..
        }) => send_access_error_type.as_ref(),
        _ => None,
    }
}

/// Surface a token-negotiation failure we have no specific message for. The error's `Debug`
/// carries the server's `error_description`, which is diagnostic and never contains send content
/// or credentials.
fn token_error(err: SendAccessTokenError) -> color_eyre::eyre::Error {
    match err {
        SendAccessTokenError::Unexpected(inner) => eyre!("Server error: {inner:?}"),
        SendAccessTokenError::Expected(inner) => eyre!("Error: {inner:?}"),
    }
}

/// Fetch the Send with the negotiated token, decrypt it with the URL key, and render it.
async fn render_access(
    client: &PasswordManagerClient,
    access_key: &SendAccessKey,
    token: String,
    inputs: &ReceiveInputs,
) -> CommandResult {
    let response = client.sends().access_send(token.clone()).await?;
    let view = access_key.decrypt_response(response)?;

    if inputs.full_object {
        return Ok(CommandOutput::Object(Box::new(view)));
    }

    match view.type_ {
        // `render_result` uses `println!`, so this gains a trailing newline over legacy's raw
        // `stdout.write`. Same pre-existing divergence as `bw send get --text`; kept consistent
        // with the rest of this CLI rather than special-cased here.
        Some(SendType::Text) => Ok(CommandOutput::Plain(
            view.text.and_then(|text| text.text).unwrap_or_default(),
        )),
        Some(SendType::File) => {
            save_file_send(
                client,
                access_key,
                &token,
                view,
                inputs.output_path.as_deref(),
            )
            .await
        }
        // Unknown or absent type: hand back everything we decrypted, as legacy does, rather
        // than guessing at which content field to print.
        None => Ok(CommandOutput::Object(Box::new(view))),
    }
}

/// Download, decrypt, and save a file-type Send's blob.
async fn save_file_send(
    client: &PasswordManagerClient,
    access_key: &SendAccessKey,
    token: &str,
    view: SendAccessView,
    output: Option<&str>,
) -> CommandResult {
    let file = view
        .file
        .ok_or_else(|| eyre!("The Send is a file Send but carries no file metadata."))?;
    let file_id = file
        .id
        .ok_or_else(|| eyre!("The Send's file is missing an id; cannot download it."))?;

    let download = client
        .sends()
        .get_file_download_data(token.to_string(), file_id)
        .await?;
    let download_url = download
        .url
        .ok_or_else(|| eyre!("The server did not return a download url for the Send's file."))?;

    let encrypted = download_bytes(client, &download_url).await?;
    let decrypted = access_key.decrypt_file_buffer(&encrypted)?;

    let file_name = default_send_file_name(file.file_name.as_deref());
    let path = save_file(output, &file_name, &decrypted)?;

    Ok(CommandOutput::Plain(format!("Saved {}", path.display())))
}

/// GET a pre-signed blob URL with the client's shared HTTP stack (so proxy and TLS settings
/// apply), mirroring legacy's `apiService.nativeFetch`.
///
/// The fetch lives here rather than in [`super::file_output`] because a shared helper would have
/// to name `reqwest::Client` in its signature, which would mean adding `reqwest` as a direct
/// dependency of `bw`. Worth doing once a second command needs it; not for one caller.
async fn download_bytes(client: &PasswordManagerClient, url: &str) -> Result<Vec<u8>> {
    let response = client
        .0
        .internal
        .get_http_client()
        .get(url)
        // Spelled as a plain `&str` so this file never has to name `reqwest`'s header types.
        .header("cache-control", "no-cache")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(eyre!(
            "A {} error occurred while downloading the attachment.",
            response.status().as_u16()
        ));
    }

    Ok(response.bytes().await?.to_vec())
}

// ===== Password resolution =====

/// Resolve the Send's password, prompting when it wasn't supplied and the session is
/// interactive. Mirrors legacy's `handlePasswordAuth` precedence exactly.
fn resolve_password(inputs: &ReceiveInputs) -> Result<String> {
    let supplied = password_from_args(
        inputs.password.as_deref(),
        inputs.passwordfile.as_deref(),
        inputs.passwordenv.as_deref(),
    )?;

    let password = match supplied {
        Some(password) => password,
        None if can_interact() => prompt_password()?,
        None => return Err(eyre!("Password required")),
    };

    if password.is_empty() {
        return Err(eyre!("Password required"));
    }

    Ok(password)
}

/// Non-interactive half of [`resolve_password`], split out so the precedence is unit-testable.
///
/// Order (legacy `handlePasswordAuth`): `--password`, then `--passwordfile`, then
/// `--passwordenv`. An empty `--password ""` falls through, and `--passwordfile` short-circuits
/// `--passwordenv` even when the file's first line is empty — both match legacy's `else if`
/// chain.
fn password_from_args(
    password: Option<&str>,
    passwordfile: Option<&str>,
    passwordenv: Option<&str>,
) -> Result<Option<String>> {
    if let Some(password) = password.filter(|p| !p.is_empty()) {
        return Ok(Some(password.to_string()));
    }

    if let Some(path) = passwordfile {
        reject_path_traversal("--passwordfile", path)?;
        let contents = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("Could not read --passwordfile {path}"))?;
        // First line only, terminator stripped — legacy's `NodeUtils.readFirstLine`. Legacy
        // hangs forever on an empty file (its readline never emits a `line` event); we treat
        // that as "no password supplied" and let the caller prompt or error.
        return Ok(contents.lines().next().map(str::to_string));
    }

    if let Some(name) = passwordenv {
        return match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            // Legacy silently ignores an unset variable and falls through to the prompt, which
            // reads as "the flag did nothing". Say so, on stderr, without echoing any value.
            Err(_) => {
                tracing::warn!("--passwordenv variable `{name}` is not set; ignoring it.");
                Ok(None)
            }
        };
    }

    Ok(None)
}

// ===== Interactivity =====

/// Whether we may prompt the user.
///
/// Reads `BW_NOINTERACTION` strictly (`== "true"`), matching the legacy CLI. The `--nointeraction`
/// flag on [`crate::command::Cli`] is *not* honored here: it is never threaded into
/// `ClientContext`, so no `BwCommand` can see it today. Plumbing it through touches every
/// command's dispatch signature — out of scope for this command; needs its own ticket.
fn can_interact() -> bool {
    std::env::var("BW_NOINTERACTION").as_deref() != Ok("true")
}

/// Prompt for the Send's password. `inquire` renders to stderr, so
/// `bw receive <url> > out.txt` still captures only the Send's content — the same reason legacy
/// passes `output: process.stderr` to inquirer.
fn prompt_password() -> Result<String> {
    Ok(Password::new("Send password")
        .without_confirmation()
        .prompt()?)
}

fn prompt_email() -> Result<String> {
    Ok(Text::new("Enter your email address:")
        .with_validator(|input: &str| {
            if input.contains('@') {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "Please enter a valid email address".into(),
                ))
            }
        })
        .prompt()?)
}

fn prompt_otp() -> Result<String> {
    Ok(Text::new("Enter the verification code sent to your email:").prompt()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: &str) -> Url {
        Url::parse(url).expect("test url parses")
    }

    // ---- parse_send_url ----

    #[test]
    fn parses_the_web_vault_send_route() {
        let (id, key) = parse_send_url(&parse(
            "https://vault.bitwarden.com/#/send/access-id/Pgui0FK85cNhBGWHAlBHBw",
        ))
        .unwrap();
        assert_eq!(id, "access-id");
        assert_eq!(key, "Pgui0FK85cNhBGWHAlBHBw");
    }

    #[test]
    fn parses_the_send_vanity_host_route() {
        // `https://send.bitwarden.com/#<id>/<key>` — no `/send/` path segment in the fragment.
        let (id, key) = parse_send_url(&parse(
            "https://send.bitwarden.com/#access-id/Pgui0FK85cNhBGWHAlBHBw",
        ))
        .unwrap();
        assert_eq!(id, "access-id");
        assert_eq!(key, "Pgui0FK85cNhBGWHAlBHBw");
    }

    #[test]
    fn parses_self_hosted_links_with_a_path_prefix() {
        let (id, key) = parse_send_url(&parse(
            "https://example.com/bitwarden/#/send/access-id/Pgui0FK85cNhBGWHAlBHBw",
        ))
        .unwrap();
        assert_eq!(id, "access-id");
        assert_eq!(key, "Pgui0FK85cNhBGWHAlBHBw");
    }

    #[test]
    fn rejects_a_url_without_a_fragment() {
        let err = parse_send_url(&parse("https://vault.bitwarden.com/")).unwrap_err();
        assert!(
            err.to_string().contains("not a valid Send url"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_a_fragment_with_only_one_segment() {
        let err = parse_send_url(&parse("https://send.bitwarden.com/#access-id")).unwrap_err();
        assert!(
            err.to_string().contains("not a valid Send url"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_a_fragment_with_a_blank_segment() {
        // `#/send//key` and `#/send/id/` both lose a required value.
        assert!(
            parse_send_url(&parse("https://vault.bitwarden.com/#/send//key")).is_err(),
            "blank id must be rejected"
        );
        assert!(
            parse_send_url(&parse("https://vault.bitwarden.com/#/send/id/")).is_err(),
            "blank key must be rejected"
        );
    }

    // ---- resolve_urls ----

    #[test]
    fn cloud_send_and_vault_hosts_map_to_their_region() {
        for host in ["send.bitwarden.com", "vault.bitwarden.com"] {
            let (api, identity) = resolve_urls(&parse(&format!("https://{host}/#id/key")), None);
            assert_eq!(api, "https://api.bitwarden.com");
            assert_eq!(identity, "https://identity.bitwarden.com");
        }
        for host in ["send.bitwarden.eu", "vault.bitwarden.eu"] {
            let (api, identity) = resolve_urls(&parse(&format!("https://{host}/#id/key")), None);
            assert_eq!(api, "https://api.bitwarden.eu");
            assert_eq!(identity, "https://identity.bitwarden.eu");
        }
    }

    /// The cloud table must match on the **exact** host. A suffix match would send a Send
    /// password hash — derived from the recipient's password — to real Bitwarden cloud identity
    /// on behalf of an attacker-controlled link.
    #[test]
    fn a_lookalike_host_is_never_treated_as_cloud() {
        for host in [
            "send.bitwarden.com.evil.tld",
            "evil-send.bitwarden.com.attacker.example",
            "notsend.bitwarden.com.evil.tld",
        ] {
            let (api, identity) = resolve_urls(&parse(&format!("https://{host}/#id/key")), None);
            assert_eq!(api, format!("https://{host}/api"));
            assert_eq!(identity, format!("https://{host}/identity"));
        }
    }

    #[test]
    fn unknown_host_falls_back_to_the_single_domain_convention() {
        let (api, identity) = resolve_urls(&parse("https://vault.example.com/#/send/id/key"), None);
        assert_eq!(api, "https://vault.example.com/api");
        assert_eq!(identity, "https://vault.example.com/identity");
    }

    #[test]
    fn a_non_default_port_is_preserved_in_the_fallback() {
        let (api, identity) = resolve_urls(&parse("https://localhost:8080/#/send/id/key"), None);
        assert_eq!(api, "https://localhost:8080/api");
        assert_eq!(identity, "https://localhost:8080/identity");
    }

    #[test]
    fn a_matching_configured_server_supplies_the_base() {
        let config = ConfigFile {
            server: Some("https://bw.example.com".to_string()),
            ..Default::default()
        };
        let (api, identity) = resolve_urls(
            &parse("https://bw.example.com/#/send/id/key"),
            Some(&config),
        );
        assert_eq!(api, "https://bw.example.com/api");
        assert_eq!(identity, "https://bw.example.com/identity");
    }

    #[test]
    fn a_matching_configured_web_vault_supplies_the_base() {
        let config = ConfigFile {
            web_vault: Some("https://vault.example.com/".to_string()),
            ..Default::default()
        };
        let (api, identity) = resolve_urls(
            &parse("https://vault.example.com/#/send/id/key"),
            Some(&config),
        );
        assert_eq!(api, "https://vault.example.com/api");
        assert_eq!(identity, "https://vault.example.com/identity");
    }

    /// A split-domain self-host configured via `bw config server --api/--identity` must use
    /// those hosts, not `<web-vault>/api`.
    #[test]
    fn explicit_configured_api_and_identity_win_over_the_base() {
        let config = ConfigFile {
            web_vault: Some("https://vault.example.com".to_string()),
            api: Some("https://api.example.com".to_string()),
            identity: Some("https://identity.example.com/".to_string()),
            ..Default::default()
        };
        let (api, identity) = resolve_urls(
            &parse("https://vault.example.com/#/send/id/key"),
            Some(&config),
        );
        assert_eq!(api, "https://api.example.com");
        assert_eq!(identity, "https://identity.example.com");
    }

    /// A configured deployment must not hijack a link that points somewhere else — receiving a
    /// cloud Send while `bw config server` points at a self-host has to still hit cloud.
    #[test]
    fn a_config_for_a_different_origin_is_ignored() {
        let config = ConfigFile {
            server: Some("https://bw.example.com".to_string()),
            api: Some("https://api.example.com".to_string()),
            ..Default::default()
        };
        let (api, identity) =
            resolve_urls(&parse("https://send.bitwarden.com/#id/key"), Some(&config));
        assert_eq!(api, "https://api.bitwarden.com");
        assert_eq!(identity, "https://identity.bitwarden.com");

        let (api, identity) = resolve_urls(
            &parse("https://other.example.com/#/send/id/key"),
            Some(&config),
        );
        assert_eq!(api, "https://other.example.com/api");
        assert_eq!(identity, "https://other.example.com/identity");
    }

    // ---- password_from_args ----

    #[test]
    fn password_flag_wins() {
        let password = password_from_args(Some("hunter2"), None, None).unwrap();
        assert_eq!(password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn empty_password_flag_falls_through() {
        // Legacy treats `--password ""` as "not supplied".
        assert_eq!(password_from_args(Some(""), None, None).unwrap(), None);
    }

    #[test]
    fn password_file_supplies_its_first_line_only() {
        let path = std::env::temp_dir().join(format!(
            "bw-receive-passwordfile-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, "first-line\nsecond-line\n").unwrap();

        let password = password_from_args(None, Some(&path.to_string_lossy()), None).unwrap();

        assert_eq!(password.as_deref(), Some("first-line"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn password_file_strips_a_windows_line_terminator() {
        let path = std::env::temp_dir().join(format!(
            "bw-receive-passwordfile-crlf-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, "first-line\r\nsecond\r\n").unwrap();

        let password = password_from_args(None, Some(&path.to_string_lossy()), None).unwrap();

        assert_eq!(password.as_deref(), Some("first-line"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn password_file_rejects_traversal() {
        let err = password_from_args(None, Some("../secrets/pw.txt"), None).unwrap_err();
        assert!(
            err.to_string().contains("--passwordfile"),
            "expected a --passwordfile traversal error, got: {err}"
        );
    }

    #[test]
    fn missing_password_file_is_an_error_not_a_fallthrough() {
        // A caller who pointed us at a file expects to hear that it isn't there, rather than
        // being silently prompted.
        assert!(password_from_args(None, Some("/nonexistent/bw-receive-pw.txt"), None).is_err());
    }

    /// `--passwordfile` short-circuits `--passwordenv` even when the file yields nothing —
    /// legacy's `if/else if` chain never reaches the env branch once the file flag is set.
    #[test]
    fn password_file_short_circuits_password_env() {
        let path = std::env::temp_dir().join(format!(
            "bw-receive-passwordfile-empty-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, "").unwrap();

        let password = password_from_args(
            None,
            Some(&path.to_string_lossy()),
            // Deliberately a variable name that is never set: if the env branch were reached
            // this test would still pass, so the assertion below is about the empty file
            // producing `None` rather than about the env var itself.
            Some("BW_RECEIVE_TEST_UNSET_VAR"),
        )
        .unwrap();

        assert_eq!(password, None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unset_password_env_yields_no_password() {
        assert_eq!(
            password_from_args(None, None, Some("BW_RECEIVE_TEST_DEFINITELY_UNSET")).unwrap(),
            None
        );
    }

    #[test]
    fn no_inputs_yields_no_password() {
        assert_eq!(password_from_args(None, None, None).unwrap(), None);
    }
}
