//! Microsoft Entra ID (Azure AD) integration for credential rotation.
//!
//! [`EntraIntegration`] rotates user passwords in a Microsoft Entra tenant via
//! the Microsoft Graph REST API using an administrative password-reset (service
//! principal client-credentials flow).
//!
//! # URL-building security
//!
//! `account_identity` is attacker-influencable opaque input and is **never**
//! string-interpolated into a URL path.  All Graph URLs that include an identity
//! are constructed with [`url::Url::path_segments_mut`] + `push(&identity)`,
//! which percent-encodes the value as a single path segment and prevents
//! path-traversal or query-injection attacks.
//!
//! # RotationByAdministrativeReset
//!
//! The service principal secret (and the Graph bearer token derived from it) is
//! used to perform an administrative password reset via
//! `PATCH /v1.0/users/{id}/passwordProfile`.  The daemon never holds or sends
//! the *current* credential of the rotated account; this is required for retry
//! convergence (see `CustomScript` docs for the reasoning).
//!
//! # Secret handling
//!
//! - The Graph bearer token, client secret, and new password are **never** logged.
//! - `EntraIntegration` wraps the `reqwest::Client` (which holds no secrets) and the `verify_probe`
//!   flag only.  Secrets are extracted from `ctx.creds` at use-time, used briefly in a form body or
//!   `Authorization` header, then dropped.
//! - The `Debug` impl on `reqwest::Client` does not emit credentials; the struct fields are safe to
//!   print.

use std::time::Duration;

use async_trait::async_trait;
use bitwarden_sensitive_value::ExposeSensitive as _;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{Integration, IntegrationError, RotateContext, TargetEffect};
use crate::error::{ErrorClass, FailureCode, SafeDetail};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default Microsoft login endpoint for token acquisition.
const DEFAULT_LOGIN_BASE: &str = "https://login.microsoftonline.com";

/// Default Microsoft Graph API base URL.
const DEFAULT_GRAPH_BASE: &str = "https://graph.microsoft.com";

/// Graph API scope for client-credentials token requests.
const GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default";

/// HTTP timeout applied to every individual request (token fetch, PATCH, GET, POST).
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Clock-slack tolerance for `lastPasswordChangeDateTime` freshness check (5 minutes).
const VERIFY_CLOCK_SLACK: chrono::Duration = chrono::Duration::seconds(300);

// ---------------------------------------------------------------------------
// EntraIntegration
// ---------------------------------------------------------------------------

/// Microsoft Entra ID integration driver.
///
/// Rotates credentials via the Graph API using the administrative password-reset
/// endpoint (`PATCH /v1.0/users/{id}/passwordProfile`).  Authentication uses a
/// service-principal client-credentials flow; the daemon's own Graph bearer token
/// is obtained once per operation invocation (no global cache).
///
/// # Secret handling
///
/// The `reqwest::Client` holds no secrets.  Secrets (tenant-id, client-id,
/// client-secret, Graph bearer, new password) are touched only inside individual
/// async operation bodies, live only on the stack, and are never stored in
/// `self`.
pub(crate) struct EntraIntegration {
    /// Shared HTTP client (built once, reused across operations).
    http: Client,
    /// Whether to attempt an ROPC verify probe after directory confirmation.
    ///
    /// Disabled by default because MFA / Conditional Access blocks it in most
    /// production tenants.  Enable with `--entra-verify-probe`.
    verify_probe: bool,
    /// Base URL for the Microsoft login (token) endpoint.  Overrideable in tests.
    login_base: String,
    /// Base URL for the Graph API.  Overrideable in tests.
    graph_base: String,
}

impl EntraIntegration {
    /// Build a new `EntraIntegration` using the production Microsoft endpoints.
    pub(crate) fn new(verify_probe: bool) -> Self {
        // Do not follow redirects: a cross-host redirect could leak the bearer token.
        let http = bitwarden_api_base::new_http_client_builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Entra HTTP client build should not fail");
        Self {
            http,
            verify_probe,
            login_base: DEFAULT_LOGIN_BASE.to_owned(),
            graph_base: DEFAULT_GRAPH_BASE.to_owned(),
        }
    }

    /// Build a new `EntraIntegration` with injectable base URLs (test helper).
    ///
    /// Points at wiremock servers instead of real Microsoft endpoints.
    #[cfg(test)]
    fn new_with_bases(verify_probe: bool, login_base: String, graph_base: String) -> Self {
        // Build (and discard) a standard client to trigger the ring crypto provider
        // global install (idempotent) inside new_http_client_builder()/build().
        // We then build a separate client for test use that works with http://
        // wiremock servers.
        let _ = bitwarden_api_base::new_http_client_builder()
            .build()
            .expect("provider install client");
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .expect("test HTTP client build should not fail");
        Self {
            http,
            verify_probe,
            login_base,
            graph_base,
        }
    }
}

impl std::fmt::Debug for EntraIntegration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntraIntegration")
            .field("verify_probe", &self.verify_probe)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Graph token acquisition
// ---------------------------------------------------------------------------

/// Fetches a Graph API bearer token using the client-credentials flow.
///
/// The client secret is sent only in the `application/x-www-form-urlencoded`
/// POST body (HTTPS encrypted) and is never stored beyond this call.
///
/// | Response              | Classification                                   |
/// |-----------------------|--------------------------------------------------|
/// | 400 / 401             | Fatal / NotApplied / target_rejected             |
/// | 429 / 5xx / network   | Transient / NotApplied / target_unreachable      |
async fn fetch_graph_token(
    http: &Client,
    login_base: &str,
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, IntegrationError> {
    let mut token_url = Url::parse(login_base).map_err(|_| IntegrationError {
        class: ErrorClass::Fatal,
        effect: TargetEffect::NotApplied,
        code: FailureCode::TargetUnreachable,
        detail: SafeDetail::from_kind("InvalidLoginBase"),
    })?;
    {
        let mut segments = token_url
            .path_segments_mut()
            .map_err(|_| IntegrationError {
                class: ErrorClass::Fatal,
                effect: TargetEffect::NotApplied,
                code: FailureCode::TargetUnreachable,
                detail: SafeDetail::from_kind("InvalidLoginBase"),
            })?;
        segments.push(tenant_id);
        segments.push("oauth2");
        segments.push("v2.0");
        segments.push("token");
    }

    // The form body contains the client_secret; we never log it.
    let form = [
        ("grant_type", "client_credentials"),
        ("scope", GRAPH_SCOPE),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];

    let response = http
        .post(token_url.as_str())
        .form(&form)
        .send()
        .await
        .map_err(|e| network_error_before_send(e, TargetEffect::NotApplied))?;

    let status = response.status();
    let status_u16 = status.as_u16();

    if status.is_success() {
        let body: TokenResponse = response.json().await.map_err(|_| IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::TargetRejected,
            detail: SafeDetail::from_http_status_and_graph_code(status_u16, None),
        })?;
        return Ok(body.access_token);
    }

    if status_u16 == 400 || status_u16 == 401 {
        Err(IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::TargetRejected,
            detail: SafeDetail::from_http_status_and_graph_code(status_u16, None),
        })
    } else {
        // 429 / 5xx
        Err(IntegrationError {
            class: ErrorClass::Transient,
            effect: TargetEffect::NotApplied,
            code: FailureCode::TargetUnreachable,
            detail: SafeDetail::from_http_status_and_graph_code(status_u16, None),
        })
    }
}

// ---------------------------------------------------------------------------
// Wire response shapes
// ---------------------------------------------------------------------------

/// Minimal OAuth2 token response; only `access_token` is consumed.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Minimal Graph user resource; only `lastPasswordChangeDateTime` is consumed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserResource {
    last_password_change_date_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Minimal Graph error envelope.
///
/// Only `error.code` is read — it is a server-assigned enum string (e.g.
/// `"Request_ResourceNotFound"`).  `error.message` is intentionally never read
/// because it can echo user-supplied content.
#[derive(Deserialize, Default)]
struct GraphError {
    #[serde(default)]
    error: GraphErrorInner,
}

#[derive(Deserialize, Default)]
struct GraphErrorInner {
    #[serde(default)]
    code: Option<String>,
}

// ---------------------------------------------------------------------------
// URL construction helpers
// ---------------------------------------------------------------------------

/// Build a Graph URL for a user identity, treating `identity` as a single
/// opaque path segment.
///
/// # Security
///
/// `identity` is attacker-influencable input (arrives from the server as
/// `accountIdentity`).  Using `push` on `path_segments_mut` ensures slashes,
/// query chars, and percent sequences in `identity` are encoded as part of the
/// segment, preventing path injection.
fn build_graph_user_url(
    graph_base: &str,
    identity: &str,
    extra_segments: &[&str],
) -> Result<Url, IntegrationError> {
    let mut url = Url::parse(graph_base).map_err(|_| IntegrationError {
        class: ErrorClass::Fatal,
        effect: TargetEffect::NotApplied,
        code: FailureCode::TargetUnreachable,
        detail: SafeDetail::from_kind("InvalidGraphBase"),
    })?;
    {
        let mut segs = url.path_segments_mut().map_err(|_| IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::TargetUnreachable,
            detail: SafeDetail::from_kind("InvalidGraphBase"),
        })?;
        segs.push("v1.0");
        segs.push("users");
        segs.push(identity);
        for &seg in extra_segments {
            segs.push(seg);
        }
    }
    Ok(url)
}

// ---------------------------------------------------------------------------
// Network error classification helpers
// ---------------------------------------------------------------------------

/// Maps a `reqwest::Error` from the connect phase (before data is sent) to an
/// `IntegrationError`.  Connect errors are always Transient.
fn network_error_before_send(e: reqwest::Error, effect: TargetEffect) -> IntegrationError {
    IntegrationError {
        class: ErrorClass::Transient,
        effect,
        code: FailureCode::TargetUnreachable,
        detail: if e.is_timeout() {
            SafeDetail::from_kind("ConnectTimeout")
        } else if e.is_connect() {
            SafeDetail::from_kind("ConnectError")
        } else {
            SafeDetail::from_kind("NetworkError")
        },
    }
}

/// Maps a `reqwest::Error` that occurred after sending a mutation request to an
/// `IntegrationError`.
///
/// After-send timeouts are classified as `Unknown` effect because the mutation
/// may have reached the server.  Connect errors (definite pre-send) remain
/// Transient / pre_send_effect.  When in doubt we prefer `Unknown`.
fn network_error_after_send(e: reqwest::Error, pre_send_effect: TargetEffect) -> IntegrationError {
    if e.is_connect() {
        IntegrationError {
            class: ErrorClass::Transient,
            effect: pre_send_effect,
            code: FailureCode::TargetUnreachable,
            detail: SafeDetail::from_kind("ConnectError"),
        }
    } else {
        IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::Unknown,
            code: FailureCode::TargetUnreachable,
            detail: if e.is_timeout() {
                SafeDetail::from_kind("ResponseTimeout")
            } else {
                SafeDetail::from_kind("NetworkError")
            },
        }
    }
}

/// Parse Graph `error.code` from a JSON error body without consuming secrets.
///
/// `error.message` is deliberately ignored — it can echo user-supplied content.
///
/// The returned code is validated against `^[A-Za-z0-9_]{1,64}$`.  A code that
/// fails validation (e.g. contains control characters, punctuation, or is too
/// long) is treated as absent — the caller includes only the HTTP status.  This
/// prevents log-injection or unexpected detail strings from attacker-influenced
/// server responses.
async fn read_graph_error_code(response: reqwest::Response) -> Option<String> {
    let body = response.bytes().await.ok()?;
    let parsed: GraphError = serde_json::from_slice(&body).ok()?;
    let code = parsed.error.code?;
    if validate_graph_error_code(&code) {
        Some(code)
    } else {
        None
    }
}

/// Returns `true` if `code` matches `^[A-Za-z0-9_]{1,64}$`.
fn validate_graph_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ---------------------------------------------------------------------------
// Integration impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Integration for EntraIntegration {
    /// Rotate the user's password via `PATCH /v1.0/users/{identity}/passwordProfile`.
    ///
    /// | Response                    | Effect     | Class     | Code              |
    /// |-----------------------------|------------|-----------|-------------------|
    /// | 200 / 204                   | —          | success   | —                 |
    /// | connect error (before send) | NotApplied | Transient | target_unreachable|
    /// | timeout after send          | Unknown    | Fatal     | target_unreachable|
    /// | 404                         | NotApplied | Fatal     | target_rejected   |
    /// | 401 / 403                   | NotApplied | Fatal     | target_rejected   |
    /// | 429 / 5xx                   | NotApplied | Transient | target_unreachable|
    async fn rotate(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let tenant_id = get_cred(&ctx.creds, "TENANT_ID")?;
        let client_id = get_cred(&ctx.creds, "CLIENT_ID")?;
        let client_secret = get_cred(&ctx.creds, "CLIENT_SECRET")?;

        let bearer = fetch_graph_token(
            &self.http,
            &self.login_base,
            tenant_id,
            client_id,
            client_secret,
        )
        .await?;

        let url = build_graph_user_url(&self.graph_base, &ctx.account_identity, &[])?;

        // The new password is sent in the JSON body; it is never logged.
        let patch_body = serde_json::json!({
            "passwordProfile": {
                "password": ctx.new_password.as_str(),
                "forceChangePasswordNextSignIn": false
            }
        });

        let response = self
            .http
            .patch(url.as_str())
            .bearer_auth(&bearer)
            .json(&patch_body)
            .send()
            .await
            .map_err(|e| network_error_after_send(e, TargetEffect::NotApplied))?;

        let status = response.status();
        let status_u16 = status.as_u16();

        if status.is_success() {
            return Ok(());
        }

        let graph_code = read_graph_error_code(response).await;
        let graph_code_ref = graph_code.as_deref();

        if status_u16 == 404 || status_u16 == 401 || status_u16 == 403 {
            Err(IntegrationError {
                class: ErrorClass::Fatal,
                effect: TargetEffect::NotApplied,
                code: FailureCode::TargetRejected,
                detail: SafeDetail::from_http_status_and_graph_code(status_u16, graph_code_ref),
            })
        } else {
            // 429, 5xx
            Err(IntegrationError {
                class: ErrorClass::Transient,
                effect: TargetEffect::NotApplied,
                code: FailureCode::TargetUnreachable,
                detail: SafeDetail::from_http_status_and_graph_code(status_u16, graph_code_ref),
            })
        }
    }

    /// Verify that the rotation applied via directory confirmation.
    ///
    /// `GET /v1.0/users/{identity}?$select=lastPasswordChangeDateTime`
    ///
    /// `lastPasswordChangeDateTime` must be present and >= `rotation_started_at`
    /// minus 5 minutes of clock slack.  If `verify_probe` is set, an ROPC grant
    /// is also attempted; `AADSTS50076` / `AADSTS50079` (MFA required — password
    /// accepted) count as verified; `AADSTS50126` → verification_failed.
    ///
    /// Verify failures carry `Applied` because the rotation step has already
    /// succeeded by the time verify runs.
    async fn verify(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let tenant_id = get_cred(&ctx.creds, "TENANT_ID")?;
        let client_id = get_cred(&ctx.creds, "CLIENT_ID")?;
        let client_secret = get_cred(&ctx.creds, "CLIENT_SECRET")?;

        let bearer = fetch_graph_token(
            &self.http,
            &self.login_base,
            tenant_id,
            client_id,
            client_secret,
        )
        .await
        .map_err(|mut e| {
            // Rotation already applied; re-classify effect to Applied.
            e.effect = TargetEffect::Applied;
            e
        })?;

        // GET /v1.0/users/{identity}?$select=lastPasswordChangeDateTime
        let mut url = build_graph_user_url(&self.graph_base, &ctx.account_identity, &[])?;
        url.set_query(Some("$select=lastPasswordChangeDateTime"));

        let response = self
            .http
            .get(url.as_str())
            .bearer_auth(&bearer)
            .send()
            .await
            .map_err(|_| IntegrationError {
                // Network error during verify: password was already changed.
                class: ErrorClass::Transient,
                effect: TargetEffect::Applied,
                code: FailureCode::TargetUnreachable,
                detail: SafeDetail::from_kind("NetworkError"),
            })?;

        let status = response.status();
        let status_u16 = status.as_u16();

        if !status.is_success() {
            let graph_code = read_graph_error_code(response).await;
            let detail =
                SafeDetail::from_http_status_and_graph_code(status_u16, graph_code.as_deref());
            // 429 / 5xx → Transient; 4xx → Fatal; all carry Applied.
            let class = if status_u16 == 429 || status_u16 >= 500 {
                ErrorClass::Transient
            } else {
                ErrorClass::Fatal
            };
            return Err(IntegrationError {
                class,
                effect: TargetEffect::Applied,
                code: FailureCode::TargetUnreachable,
                detail,
            });
        }

        let user: UserResource = response.json().await.map_err(|_| IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::Applied,
            code: FailureCode::VerificationFailed,
            detail: SafeDetail::from_http_status_and_graph_code(status_u16, None),
        })?;

        // Directory-based verification: lastPasswordChangeDateTime must be fresh.
        let directory_ok = match user.last_password_change_date_time {
            Some(changed_at) => {
                let earliest_acceptable = ctx.rotation_started_at - VERIFY_CLOCK_SLACK;
                changed_at >= earliest_acceptable
            }
            None => false,
        };

        // ROPC probe (optional).
        if self.verify_probe {
            let probe_result = ropc_probe(
                &self.http,
                &self.login_base,
                tenant_id,
                client_id,
                &ctx.account_identity,
                ctx.new_password.as_str(),
            )
            .await;

            match probe_result {
                ProbeResult::Verified => return Ok(()),
                ProbeResult::WrongPassword => {
                    return Err(IntegrationError {
                        class: ErrorClass::Fatal,
                        effect: TargetEffect::Applied,
                        code: FailureCode::VerificationFailed,
                        detail: SafeDetail::from_kind("RopcWrongPassword"),
                    });
                }
                ProbeResult::Inconclusive => {
                    // Fall through to directory result.
                }
            }
        }

        if directory_ok {
            Ok(())
        } else {
            Err(IntegrationError {
                class: ErrorClass::Fatal,
                effect: TargetEffect::Applied,
                code: FailureCode::VerificationFailed,
                detail: SafeDetail::from_kind("StalePasswordChangeTimestamp"),
            })
        }
    }

    /// Revoke all active sign-in sessions for `ctx.account_identity`.
    ///
    /// `POST /v1.0/users/{identity}/revokeSignInSessions`
    ///
    /// Session termination never changes the credential, so all errors carry
    /// `NotApplied`.
    async fn terminate_sessions(&self, ctx: &RotateContext) -> Result<(), IntegrationError> {
        let tenant_id = get_cred(&ctx.creds, "TENANT_ID")?;
        let client_id = get_cred(&ctx.creds, "CLIENT_ID")?;
        let client_secret = get_cred(&ctx.creds, "CLIENT_SECRET")?;

        let bearer = fetch_graph_token(
            &self.http,
            &self.login_base,
            tenant_id,
            client_id,
            client_secret,
        )
        .await?;

        let url = build_graph_user_url(
            &self.graph_base,
            &ctx.account_identity,
            &["revokeSignInSessions"],
        )?;

        let response = self
            .http
            .post(url.as_str())
            .bearer_auth(&bearer)
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(|e| network_error_before_send(e, TargetEffect::NotApplied))?;

        let status = response.status();
        let status_u16 = status.as_u16();

        if status.is_success() {
            return Ok(());
        }

        let graph_code = read_graph_error_code(response).await;
        let detail = SafeDetail::from_http_status_and_graph_code(status_u16, graph_code.as_deref());

        if status_u16 == 429 || status_u16 >= 500 {
            Err(IntegrationError {
                class: ErrorClass::Transient,
                effect: TargetEffect::NotApplied,
                code: FailureCode::TargetUnreachable,
                detail,
            })
        } else {
            // 4xx
            Err(IntegrationError {
                class: ErrorClass::Fatal,
                effect: TargetEffect::NotApplied,
                code: FailureCode::TargetRejected,
                detail,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// ROPC probe helper
// ---------------------------------------------------------------------------

/// Result of the ROPC (Resource Owner Password Credentials) verify probe.
#[derive(Debug, PartialEq, Eq)]
enum ProbeResult {
    /// Password accepted (or MFA required — confirming the password is correct).
    Verified,
    /// Password explicitly rejected (`AADSTS50126`).
    WrongPassword,
    /// Outcome inconclusive; fall back to the directory check.
    Inconclusive,
}

/// Attempts an ROPC grant to verify the new password was accepted.
///
/// The new password is sent **only** in the form body (HTTPS encrypted); it is
/// never stored, logged, or returned.
///
/// | AADSTS code    | Meaning                              | Result       |
/// |----------------|--------------------------------------|--------------|
/// | AADSTS50076    | MFA required (password accepted)     | Verified     |
/// | AADSTS50079    | MFA setup required (password accepted)| Verified    |
/// | AADSTS50126    | Invalid username/password            | WrongPassword|
/// | other AADSTS   | Policy, account state, etc.          | Inconclusive |
/// | network / 5xx  | Transport issue                      | Inconclusive |
async fn ropc_probe(
    http: &Client,
    login_base: &str,
    tenant_id: &str,
    client_id: &str,
    account_identity: &str,
    new_password: &str,
) -> ProbeResult {
    let mut token_url = match Url::parse(login_base) {
        Ok(u) => u,
        Err(_) => return ProbeResult::Inconclusive,
    };
    match token_url.path_segments_mut() {
        Ok(mut segs) => {
            segs.push(tenant_id);
            segs.push("oauth2");
            segs.push("v2.0");
            segs.push("token");
        }
        Err(_) => return ProbeResult::Inconclusive,
    }

    // The form contains the new password; it is never stored or logged.
    let form = [
        ("grant_type", "password"),
        ("scope", GRAPH_SCOPE),
        ("client_id", client_id),
        ("username", account_identity),
        ("password", new_password),
    ];

    let response = match http.post(token_url.as_str()).form(&form).send().await {
        Ok(r) => r,
        Err(_) => return ProbeResult::Inconclusive,
    };

    if response.status().is_success() {
        // Token issued without MFA challenge — password accepted.
        return ProbeResult::Verified;
    }

    // Parse AADSTS code from `error_description`.
    // Format: "AADSTS50126: Error validating credentials…" — we take only the
    // first colon/whitespace-delimited token, which is the AADSTS identifier.
    let body = match response.bytes().await {
        Ok(b) => b,
        Err(_) => return ProbeResult::Inconclusive,
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return ProbeResult::Inconclusive,
    };

    if let Some(desc) = parsed.get("error_description").and_then(|v| v.as_str()) {
        let aadsts_code = desc
            .split(|c: char| c == ':' || c.is_whitespace())
            .next()
            .unwrap_or("");

        return match aadsts_code {
            "AADSTS50076" | "AADSTS50079" => ProbeResult::Verified,
            "AADSTS50126" => ProbeResult::WrongPassword,
            _ => ProbeResult::Inconclusive,
        };
    }

    ProbeResult::Inconclusive
}

// ---------------------------------------------------------------------------
// Credential lookup helper
// ---------------------------------------------------------------------------

/// Look up a required credential suffix, returning
/// `Fatal/NotApplied/credentials_unresolved` if absent.
///
/// The error detail names only the missing **suffix** (never a value).
fn get_cred<'a>(
    creds: &'a crate::resolver::ResolvedCredentials,
    suffix: &'static str,
) -> Result<&'a str, IntegrationError> {
    creds
        .get(suffix)
        .map(|s| s.expose().as_ref() as &str)
        .ok_or_else(|| IntegrationError {
            class: ErrorClass::Fatal,
            effect: TargetEffect::NotApplied,
            code: FailureCode::CredentialsUnresolved,
            detail: SafeDetail::from_kind(suffix),
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path, query_param},
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        error::{ErrorClass, FailureCode},
        integrations::{RotateContext, TargetEffect},
        resolver::ResolvedCredentials,
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_creds(tenant: &str, client_id: &str, secret: &str) -> ResolvedCredentials {
        let mut creds = ResolvedCredentials::new();
        creds.insert("TENANT_ID".to_string(), tenant.to_string());
        creds.insert("CLIENT_ID".to_string(), client_id.to_string());
        creds.insert("CLIENT_SECRET".to_string(), secret.to_string());
        creds
    }

    fn make_ctx(creds: ResolvedCredentials, identity: &str, new_password: &str) -> RotateContext {
        RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: identity.to_string(),
            new_password: Zeroizing::new(new_password.to_string()),
            creds,
            rotation_started_at: Utc::now(),
        }
    }

    fn make_ctx_started_at(
        creds: ResolvedCredentials,
        identity: &str,
        new_password: &str,
        rotation_started_at: chrono::DateTime<Utc>,
    ) -> RotateContext {
        RotateContext {
            target_system_id: Uuid::nil(),
            account_identity: identity.to_string(),
            new_password: Zeroizing::new(new_password.to_string()),
            creds,
            rotation_started_at,
        }
    }

    async fn mount_token_ok(server: &MockServer, tenant: &str, bearer: &str) {
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "access_token": bearer }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(server)
            .await;
    }

    fn integration(login: &MockServer, graph: &MockServer, verify_probe: bool) -> EntraIntegration {
        EntraIntegration::new_with_bases(verify_probe, login.uri(), graph.uri())
    }

    // -----------------------------------------------------------------------
    // Token fetch: form fields
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn token_fetch_sends_correct_form_fields() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "my-tenant";

        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains(
                "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
            ))
            .and(body_string_contains("client_id=test-client"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "access_token": "tok" }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&login)
            .await;

        Mock::given(method("PATCH"))
            .and(path("/v1.0/users/user@example.com"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "test-client", "test-secret");
        let ctx = make_ctx(creds, "user@example.com", "NewPass123!");
        let integ = integration(&login, &graph, false);
        integ.rotate(&ctx).await.unwrap();
    }

    // -----------------------------------------------------------------------
    // rotate: PATCH body + 204 success
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_patch_body_and_success() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "bearer-tok").await;

        Mock::given(method("PATCH"))
            .and(path("/v1.0/users/user@example.com"))
            .and(body_string_contains("passwordProfile"))
            .and(body_string_contains("forceChangePasswordNextSignIn"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "user@example.com", "Rotated@Pass1");
        let integ = integration(&login, &graph, false);
        assert!(integ.rotate(&ctx).await.is_ok());
    }

    // -----------------------------------------------------------------------
    // rotate: 200 is also success
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_200_is_success() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "bearer-tok").await;

        Mock::given(method("PATCH"))
            .and(path("/v1.0/users/user@example.com"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "user@example.com", "NewPass1");
        let integ = integration(&login, &graph, false);
        assert!(integ.rotate(&ctx).await.is_ok());
    }

    // -----------------------------------------------------------------------
    // rotate: 404 → Fatal / NotApplied / target_rejected
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_404_gives_fatal_not_applied_target_rejected() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        Mock::given(method("PATCH"))
            .and(path("/v1.0/users/missing-user"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": {
                    "code": "Request_ResourceNotFound",
                    "message": "Resource does not exist"
                }
            })))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "missing-user", "P@ss1");
        let integ = integration(&login, &graph, false);
        let err = integ.rotate(&ctx).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, FailureCode::TargetRejected);
    }

    // -----------------------------------------------------------------------
    // rotate: 403 → Fatal / NotApplied / target_rejected
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_403_gives_fatal_not_applied_target_rejected() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        Mock::given(method("PATCH"))
            .and(path("/v1.0/users/some-user"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "some-user", "P@ss1");
        let integ = integration(&login, &graph, false);
        let err = integ.rotate(&ctx).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, FailureCode::TargetRejected);
    }

    // -----------------------------------------------------------------------
    // rotate: 429 → Transient / NotApplied / target_unreachable
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_429_gives_transient_not_applied() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        Mock::given(method("PATCH"))
            .and(path("/v1.0/users/some-user"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "some-user", "P@ss1");
        let integ = integration(&login, &graph, false);
        let err = integ.rotate(&ctx).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Transient);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, FailureCode::TargetUnreachable);
    }

    // -----------------------------------------------------------------------
    // verify: fresh lastPasswordChangeDateTime → Ok
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_accepts_fresh_last_password_change() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        let now = Utc::now();
        let changed_at = (now + chrono::Duration::seconds(10)).to_rfc3339();

        Mock::given(method("GET"))
            .and(path("/v1.0/users/user@example.com"))
            .and(query_param("$select", "lastPasswordChangeDateTime"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "lastPasswordChangeDateTime": changed_at
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx_started_at(creds, "user@example.com", "P@ss1", now);
        let integ = integration(&login, &graph, false);
        assert!(integ.verify(&ctx).await.is_ok());
    }

    // -----------------------------------------------------------------------
    // verify: stale lastPasswordChangeDateTime → Applied + verification_failed
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_rejects_stale_last_password_change() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        let now = Utc::now();
        let stale_at = (now - chrono::Duration::minutes(10)).to_rfc3339();

        Mock::given(method("GET"))
            .and(path("/v1.0/users/user@example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "lastPasswordChangeDateTime": stale_at
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx_started_at(creds, "user@example.com", "P@ss1", now);
        let integ = integration(&login, &graph, false);
        let err = integ.verify(&ctx).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::Applied);
        assert_eq!(err.code, FailureCode::VerificationFailed);
    }

    // -----------------------------------------------------------------------
    // verify: missing lastPasswordChangeDateTime → Applied + verification_failed
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_rejects_missing_last_password_change() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        Mock::given(method("GET"))
            .and(path("/v1.0/users/user@example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({}))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "user@example.com", "P@ss1");
        let integ = integration(&login, &graph, false);
        let err = integ.verify(&ctx).await.unwrap_err();
        assert_eq!(err.effect, TargetEffect::Applied);
        assert_eq!(err.code, FailureCode::VerificationFailed);
    }

    // -----------------------------------------------------------------------
    // verify probe: AADSTS50076 (MFA required) counts as verified
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_probe_aadsts50076_counts_as_verified() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        // Mount ROPC mock FIRST so wiremock prioritises it over the catch-all
        // client_credentials mock that follows.
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .and(body_string_contains("grant_type=password"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({
                        "error": "interaction_required",
                        "error_description": "AADSTS50076: Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access this resource."
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&login)
            .await;

        // Client-credentials token for Graph GET (catch-all, lower priority).
        mount_token_ok(&login, tenant, "graph-tok").await;

        // Directory GET: stale → without probe this would fail.
        let stale_at = (Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
        Mock::given(method("GET"))
            .and(path("/v1.0/users/user@example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "lastPasswordChangeDateTime": stale_at
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "user@example.com", "P@ss1");
        let integ = integration(&login, &graph, true);
        // Probe got AADSTS50076 → Verified regardless of directory timestamp.
        assert!(integ.verify(&ctx).await.is_ok());
    }

    // -----------------------------------------------------------------------
    // verify probe: AADSTS50126 (wrong password) → verification_failed
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_probe_aadsts50126_gives_verification_failed() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        // Mount ROPC mock FIRST so wiremock's priority favours it over the
        // catch-all client_credentials mock below.
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .and(body_string_contains("grant_type=password"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "AADSTS50126: Invalid username or password or Invalid on-premise username or password."
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&login)
            .await;

        mount_token_ok(&login, tenant, "graph-tok").await;

        // Directory GET: fresh timestamp.
        let now = Utc::now();
        let fresh_at = (now + chrono::Duration::seconds(1)).to_rfc3339();
        Mock::given(method("GET"))
            .and(path("/v1.0/users/user@example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "lastPasswordChangeDateTime": fresh_at
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx_started_at(creds, "user@example.com", "P@ss1", now);
        let integ = integration(&login, &graph, true);
        let err = integ.verify(&ctx).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::Applied);
        assert_eq!(err.code, FailureCode::VerificationFailed);
    }

    // -----------------------------------------------------------------------
    // terminate_sessions: 204 success
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn terminate_sessions_success_204() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        Mock::given(method("POST"))
            .and(path("/v1.0/users/user@example.com/revokeSignInSessions"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "user@example.com", "P@ss1");
        let integ = integration(&login, &graph, false);
        assert!(integ.terminate_sessions(&ctx).await.is_ok());
    }

    // -----------------------------------------------------------------------
    // terminate_sessions: 200 success
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn terminate_sessions_success_200() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        Mock::given(method("POST"))
            .and(path("/v1.0/users/user@example.com/revokeSignInSessions"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": true})),
            )
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "user@example.com", "P@ss1");
        let integ = integration(&login, &graph, false);
        assert!(integ.terminate_sessions(&ctx).await.is_ok());
    }

    // -----------------------------------------------------------------------
    // terminate_sessions: 4xx → Fatal / NotApplied / target_rejected
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn terminate_sessions_4xx_gives_fatal_not_applied() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        Mock::given(method("POST"))
            .and(path("/v1.0/users/user@example.com/revokeSignInSessions"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "user@example.com", "P@ss1");
        let integ = integration(&login, &graph, false);
        let err = integ.terminate_sessions(&ctx).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, FailureCode::TargetRejected);
    }

    // -----------------------------------------------------------------------
    // terminate_sessions: 429 → Transient / NotApplied
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn terminate_sessions_429_gives_transient() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        Mock::given(method("POST"))
            .and(path("/v1.0/users/user@example.com/revokeSignInSessions"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "user@example.com", "P@ss1");
        let integ = integration(&login, &graph, false);
        let err = integ.terminate_sessions(&ctx).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Transient);
        assert_eq!(err.effect, TargetEffect::NotApplied);
    }

    // -----------------------------------------------------------------------
    // Hostile identity URL encoding
    // -----------------------------------------------------------------------

    #[test]
    fn hostile_identity_slash_encoded() {
        let url = build_graph_user_url("https://graph.microsoft.com", "a/b", &[]).unwrap();
        let path = url.path();
        assert!(
            path.contains("a%2Fb") || path.contains("a%2fb"),
            "slash must be percent-encoded: {path}"
        );
        assert!(
            !path.ends_with("/b"),
            "raw slash must not split path: {path}"
        );
    }

    #[test]
    fn hostile_identity_dotdot_does_not_traverse() {
        let url = build_graph_user_url("https://graph.microsoft.com", "..", &[]).unwrap();
        assert!(
            !url.as_str().contains("/../"),
            "dotdot must not appear as a path traversal: {url}"
        );
    }

    #[test]
    fn hostile_identity_query_char_encoded() {
        let url = build_graph_user_url("https://graph.microsoft.com", "x?$filter=1", &[]).unwrap();
        let path = url.path();
        assert!(
            path.contains("x%3F") || path.contains("x%3f"),
            "query char must be encoded in path segment: {path}"
        );
        assert!(
            url.query().map(|q| !q.contains("$filter")).unwrap_or(true),
            "injected query must not appear in URL query: {url}"
        );
    }

    #[test]
    fn hostile_identity_percent_encoded_dotdot_not_decoded() {
        let url = build_graph_user_url("https://graph.microsoft.com", "%2e%2e", &[]).unwrap();
        assert!(
            !url.as_str().contains("/../"),
            "percent-encoded dotdot must not resolve to traversal: {url}"
        );
    }

    // -----------------------------------------------------------------------
    // Detail: contains status + graph error.code, NOT error.message content
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn detail_contains_status_and_graph_code_not_message() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        let sensitive_message = "super-secret-account-name-that-must-not-leak";
        Mock::given(method("PATCH"))
            .and(path("/v1.0/users/some-user"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": {
                    "code": "Request_ResourceNotFound",
                    "message": sensitive_message
                }
            })))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "some-user", "P@ss1");
        let integ = integration(&login, &graph, false);
        let err = integ.rotate(&ctx).await.unwrap_err();

        let detail = err.detail.as_str();
        assert!(
            detail.contains("404"),
            "detail must contain status code: {detail}"
        );
        assert!(
            detail.contains("Request_ResourceNotFound"),
            "detail must contain graph error code: {detail}"
        );
        assert!(
            !detail.contains(sensitive_message),
            "error.message must not appear in detail: {detail}"
        );
    }

    // -----------------------------------------------------------------------
    // Missing credentials → credentials_unresolved
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn missing_tenant_id_gives_credentials_unresolved() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;

        let mut creds = ResolvedCredentials::new();
        creds.insert("CLIENT_ID".to_string(), "cid".to_string());
        creds.insert("CLIENT_SECRET".to_string(), "secret".to_string());
        // TENANT_ID absent.

        let ctx = make_ctx(creds, "user@example.com", "P@ss1");
        let integ = integration(&login, &graph, false);
        let err = integ.rotate(&ctx).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Fatal);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, FailureCode::CredentialsUnresolved);
        assert!(
            err.detail.as_str().contains("TENANT_ID"),
            "detail must name the missing suffix: {}",
            err.detail
        );
    }

    // -----------------------------------------------------------------------
    // Fix-6: Graph error.code validation
    // -----------------------------------------------------------------------

    /// Hostile `error.code` values (control chars, punctuation, >64 chars)
    /// must be rejected and the detail must not include the hostile code.
    #[tokio::test]
    async fn hostile_graph_error_code_is_omitted_from_detail() {
        let login = MockServer::start().await;
        let graph = MockServer::start().await;
        let tenant = "t1";

        mount_token_ok(&login, tenant, "tok").await;

        // Hostile code: contains newline + very long + special chars.
        let hostile_code = "Inject\r\nEvil: value\x00\x01".repeat(5); // >64 chars with control chars
        Mock::given(method("PATCH"))
            .and(path("/v1.0/users/some-user"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": {
                    "code": hostile_code,
                    "message": "some message"
                }
            })))
            .mount(&graph)
            .await;

        let creds = make_creds(tenant, "cid", "csecret");
        let ctx = make_ctx(creds, "some-user", "P@ss1");
        let integ = integration(&login, &graph, false);
        let err = integ.rotate(&ctx).await.unwrap_err();

        let detail = err.detail.as_str();
        // Status must appear.
        assert!(
            detail.contains("404"),
            "detail must contain status code: {detail}"
        );
        // Hostile code must NOT appear in the detail.
        assert!(
            !detail.contains("Inject"),
            "hostile graph error.code must not appear in detail: {detail}"
        );
    }

    /// A valid `error.code` (alphanumeric + underscores, ≤64 chars) must be
    /// included in the detail.
    #[test]
    fn valid_graph_error_code_passes_validation() {
        assert!(super::validate_graph_error_code("Request_ResourceNotFound"));
        assert!(super::validate_graph_error_code("A"));
        assert!(super::validate_graph_error_code(&"x".repeat(64)));
    }

    /// Invalid `error.code` values must be rejected.
    #[test]
    fn invalid_graph_error_codes_are_rejected() {
        // Too long (65 chars)
        assert!(!super::validate_graph_error_code(&"x".repeat(65)));
        // Empty string
        assert!(!super::validate_graph_error_code(""));
        // Contains newline
        assert!(!super::validate_graph_error_code("Code\nInjection"));
        // Contains colon
        assert!(!super::validate_graph_error_code("Bad:Code"));
        // Contains null byte
        assert!(!super::validate_graph_error_code("Code\x00bad"));
        // Contains space
        assert!(!super::validate_graph_error_code("Bad Code"));
    }
}
