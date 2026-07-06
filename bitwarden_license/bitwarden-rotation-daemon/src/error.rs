//! Error taxonomy for the rotation daemon.
//!
//! This module defines:
//! - [`FailureCode`]: failure reason codes reported to the server on a failed rotation attempt.
//! - [`SyncState`]: vault-to-target synchronisation state at the time of a failure report.
//! - [`SessionTermination`]: outcome of the best-effort session-termination step.
//! - [`ErrorClass`]: transient vs. fatal classification used by the retry helpers.
//! - [`SafeDetail`]: a bounded, zero-knowledge detail string constructible only from vetted
//!   scalars.
//! - [`RotationDaemonError`]: top-level CLI/startup errors.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Wire enums (C3: final encoding is pinned by the generated bitwarden-api-api
// models; the api layer maps these if the generated enum variants differ)
// ---------------------------------------------------------------------------

/// Failure reason reported to the server when a rotation attempt does not succeed.
///
/// Serialised as `snake_case` over the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FailureCode {
    /// No active session at the start of execution (terminal session state).
    NoActiveSession,
    /// Target-system credentials could not be resolved from the configured resolver.
    CredentialsUnresolved,
    /// The password policy received from the server is invalid or cannot be satisfied.
    InvalidPolicy,
    /// The target-system kind is not supported by this daemon build.
    UnsupportedKind,
    /// The target system explicitly rejected the rotation (e.g. wrong account, policy
    /// violation at the target).
    TargetRejected,
    /// The target system could not be reached (network or connectivity error).
    TargetUnreachable,
    /// Verification of the rotated credential failed after the rotation step.
    VerificationFailed,
    /// A custom script exited with a failure code.
    ScriptFailed,
    /// A custom script exceeded its configured timeout.
    ScriptTimeout,
    /// The server rejected the cipher write (e.g. revision-date conflict).
    CipherWriteRejected,
    /// Encrypting the updated cipher data failed.
    CipherEncryptFailed,
    /// An unexpected internal error occurred.
    Internal,
}

/// Vault-to-target synchronisation state reported alongside a failure.
///
/// Tells the server whether the target system's credential was changed before the attempt
/// failed, allowing it (and the operator) to know whether the vault and target are in sync.
///
/// Serialised as `snake_case` over the wire.
///
/// **C3 note**: final wire encoding is pinned by the generated bitwarden-api-api models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SyncState {
    /// The target system's credential was not changed; vault and target remain in sync.
    TargetUnchanged,
    /// The target system's credential was successfully changed but the vault was not
    /// updated, so they are out of sync.
    TargetUpdated,
    /// It is not known whether the target system's credential was changed (e.g. a timeout
    /// occurred after the rotation request was submitted but before a response was received).
    Indeterminate,
}

/// Outcome of the best-effort session-termination step (step 6 of `ExecuteRotation`).
///
/// A termination failure never fails the overall rotation — the step returns this value
/// rather than propagating an error.
///
/// Serialised as `snake_case` over the wire.
///
/// **C3 note / D3**: `TermFailed` is also reported when termination was never initiated at
/// all (e.g. the `execute_by` lease expired or a connectivity pause occurred before step 6
/// could begin). This is deliberate bounded-enum widening: it is the only honest value in
/// the bounded enum when the step did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SessionTermination {
    /// Session termination was not requested (the `terminate_sessions` flag was not set).
    NotRequested,
    /// Session termination completed successfully.
    Terminated,
    /// Session termination failed, or was never initiated (see D3 above).
    TermFailed,
}

// ---------------------------------------------------------------------------
// Retry classification
// ---------------------------------------------------------------------------

/// Classifies an integration or server error as transient (eligible for local retry) or
/// fatal (retry would not help; propagate immediately).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorClass {
    /// The error is likely temporary; the operation may be retried after a delay.
    Transient,
    /// The error is permanent; retrying would not help.
    Fatal,
}

// ---------------------------------------------------------------------------
// SafeDetail
// ---------------------------------------------------------------------------

/// A bounded, zero-knowledge detail string that may be included in a failure report.
///
/// # Safety contract
///
/// Raw target-system output (stdout, stderr, error messages from remote APIs) can echo
/// credentials back. `SafeDetail` is constructible **only** from vetted scalars — HTTP
/// status codes, process exit codes, environment variable *names* (not values), error kind
/// names — so that no secret can flow into a report by construction.
///
/// There is deliberately no `From<String>` or `From<&str>` impl, and the inner field is
/// private.
///
/// The server truncates detail strings at 500 chars server-side as well; we enforce the
/// limit locally so callers never silently produce an oversized payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafeDetail(String);

impl SafeDetail {
    /// Maximum byte length of a detail string (server contract).
    pub(crate) const MAX_LEN: usize = 500;

    /// Truncates `s` to [`Self::MAX_LEN`] characters (Unicode-aware).
    fn truncate(s: String) -> String {
        if s.len() <= Self::MAX_LEN {
            s
        } else {
            // Truncate on a char boundary.
            let mut end = Self::MAX_LEN;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            s[..end].to_owned()
        }
    }

    /// Build a detail from an HTTP status code.
    #[cfg(test)]
    pub(crate) fn from_status(status: u16) -> Self {
        Self(Self::truncate(format!("HTTP {status}")))
    }

    /// Build a detail from a process exit code (custom script integration).
    pub(crate) fn from_exit_code(code: i32) -> Self {
        Self(Self::truncate(format!("exit code {code}")))
    }

    /// Build a detail from the names of missing environment variables.
    ///
    /// Variable **names** are safe; values are never included.
    pub(crate) fn from_missing_vars(names: &[String]) -> Self {
        let joined = names.join(", ");
        Self(Self::truncate(format!("missing vars: {joined}")))
    }

    /// Build a detail from an opaque error kind name (a `'static` string constant such
    /// as `"GraphRequest"` or `"ParseError"` — never a user-supplied string).
    pub(crate) fn from_kind(kind: &'static str) -> Self {
        Self(Self::truncate(format!("error kind: {kind}")))
    }

    /// Build a detail indicating a timeout after the given number of seconds.
    pub(crate) fn timed_out(secs: u64) -> Self {
        Self(Self::truncate(format!("timed out after {secs}s")))
    }

    /// Build a detail from an HTTP status code and an optional Graph `error.code`
    /// string.
    ///
    /// Only the status code (an integer) and the Graph error code (a static-safe
    /// server-assigned string like `"Request_ResourceNotFound"`) are included.
    /// The Graph `error.message` field is **never** included because it can echo
    /// user-supplied content (e.g. account identities, policy text).
    pub(crate) fn from_http_status_and_graph_code(
        status: u16,
        graph_code: Option<&str>,
    ) -> Self {
        let s = match graph_code {
            Some(code) => format!("HTTP {status} ({code})"),
            None => format!("HTTP {status}"),
        };
        Self(Self::truncate(s))
    }

    /// Returns the detail string as a `&str`.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

// Implement Display so it can be included in log messages, but explicitly do NOT implement
// Display for upstream error objects (those could echo secrets).
impl std::fmt::Display for SafeDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Top-level daemon error
// ---------------------------------------------------------------------------

/// Top-level errors produced during CLI parsing and daemon startup.
///
/// These are printed to stderr and result in a non-zero exit code. No
/// `#[bitwarden_error]` attribute is needed — the daemon has no language bindings.
#[derive(Debug, Error)]
pub enum RotationDaemonError {
    /// The configuration supplied is invalid (bad URL, conflicting options, etc.).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The daemon token string could not be parsed.
    #[error("invalid daemon token: {0}")]
    InvalidToken(String),

    /// The identity server could not be reached during startup authentication.
    #[error("identity server unreachable: {0}")]
    IdentityUnreachable(String),

    /// The daemon credential was rejected by the identity server.
    #[error("credential refused by identity server: {0}")]
    CredentialRefused(String),

    /// An I/O error occurred (e.g. reading a token file).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SafeDetail ---

    #[test]
    fn safe_detail_from_status() {
        let d = SafeDetail::from_status(429);
        assert_eq!(d.as_str(), "HTTP 429");
    }

    #[test]
    fn safe_detail_from_exit_code() {
        let d = SafeDetail::from_exit_code(2);
        assert_eq!(d.as_str(), "exit code 2");
    }

    #[test]
    fn safe_detail_from_missing_vars() {
        let vars = vec!["FOO_CLIENT_ID".to_owned(), "FOO_CLIENT_SECRET".to_owned()];
        let d = SafeDetail::from_missing_vars(&vars);
        assert_eq!(d.as_str(), "missing vars: FOO_CLIENT_ID, FOO_CLIENT_SECRET");
    }

    #[test]
    fn safe_detail_from_kind() {
        let d = SafeDetail::from_kind("GraphRequest");
        assert_eq!(d.as_str(), "error kind: GraphRequest");
    }

    #[test]
    fn safe_detail_timed_out() {
        let d = SafeDetail::timed_out(60);
        assert_eq!(d.as_str(), "timed out after 60s");
    }

    #[test]
    fn safe_detail_truncated_at_500_chars() {
        // Build a string longer than 500 chars using only ASCII so char == byte.
        let long = "x".repeat(600);
        let d = SafeDetail::from_kind(Box::leak(long.into_boxed_str()));
        assert_eq!(
            d.as_str().len(),
            SafeDetail::MAX_LEN,
            "detail must be capped at MAX_LEN"
        );
    }

    #[test]
    fn safe_detail_exactly_500_chars_not_truncated() {
        let exactly = "a".repeat(500);
        // from_missing_vars adds a prefix; use from_kind with a leaked str for exactness.
        let d = SafeDetail(SafeDetail::truncate(exactly.clone()));
        assert_eq!(d.as_str().len(), 500);
    }

    #[test]
    fn safe_detail_truncation_respects_char_boundary() {
        // Build a string where the 500-byte mark falls inside a 2-byte char (é = 0xC3 0xA9).
        // Pad to 499 ASCII bytes then append multi-byte chars.
        let base = "a".repeat(499);
        let long = base + &"é".repeat(10); // each é is 2 bytes → total > 500
        let d = SafeDetail(SafeDetail::truncate(long));
        assert!(
            d.as_str().len() <= SafeDetail::MAX_LEN,
            "truncated string must not exceed MAX_LEN bytes"
        );
        // Confirm it's valid UTF-8 (would panic on as_str() otherwise, but be explicit).
        assert!(std::str::from_utf8(d.as_str().as_bytes()).is_ok());
    }

    // --- Serde snake_case encoding ---

    #[test]
    fn failure_code_serde_snake_case() {
        let pairs: &[(FailureCode, &str)] = &[
            (FailureCode::NoActiveSession, "\"no_active_session\""),
            (
                FailureCode::CredentialsUnresolved,
                "\"credentials_unresolved\"",
            ),
            (FailureCode::InvalidPolicy, "\"invalid_policy\""),
            (FailureCode::UnsupportedKind, "\"unsupported_kind\""),
            (FailureCode::TargetRejected, "\"target_rejected\""),
            (FailureCode::TargetUnreachable, "\"target_unreachable\""),
            (FailureCode::VerificationFailed, "\"verification_failed\""),
            (FailureCode::ScriptFailed, "\"script_failed\""),
            (FailureCode::ScriptTimeout, "\"script_timeout\""),
            (
                FailureCode::CipherWriteRejected,
                "\"cipher_write_rejected\"",
            ),
            (
                FailureCode::CipherEncryptFailed,
                "\"cipher_encrypt_failed\"",
            ),
            (FailureCode::Internal, "\"internal\""),
        ];
        for (variant, expected) in pairs {
            let serialised = serde_json::to_string(variant).unwrap();
            assert_eq!(&serialised, expected, "FailureCode::{variant:?}");
            let roundtrip: FailureCode = serde_json::from_str(&serialised).unwrap();
            assert_eq!(roundtrip, *variant);
        }
    }

    #[test]
    fn sync_state_serde_snake_case() {
        let pairs: &[(SyncState, &str)] = &[
            (SyncState::TargetUnchanged, "\"target_unchanged\""),
            (SyncState::TargetUpdated, "\"target_updated\""),
            (SyncState::Indeterminate, "\"indeterminate\""),
        ];
        for (variant, expected) in pairs {
            let serialised = serde_json::to_string(variant).unwrap();
            assert_eq!(&serialised, expected, "SyncState::{variant:?}");
            let roundtrip: SyncState = serde_json::from_str(&serialised).unwrap();
            assert_eq!(roundtrip, *variant);
        }
    }

    #[test]
    fn session_termination_serde_snake_case() {
        let pairs: &[(SessionTermination, &str)] = &[
            (SessionTermination::NotRequested, "\"not_requested\""),
            (SessionTermination::Terminated, "\"terminated\""),
            (SessionTermination::TermFailed, "\"term_failed\""),
        ];
        for (variant, expected) in pairs {
            let serialised = serde_json::to_string(variant).unwrap();
            assert_eq!(&serialised, expected, "SessionTermination::{variant:?}");
            let roundtrip: SessionTermination = serde_json::from_str(&serialised).unwrap();
            assert_eq!(roundtrip, *variant);
        }
    }
}
