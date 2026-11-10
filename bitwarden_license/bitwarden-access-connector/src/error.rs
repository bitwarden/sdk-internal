//! Error taxonomy: retry classification, safe report details, and startup errors.

use thiserror::Error;

/// Whether an integration or server error is worth a local retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorClass {
    /// The error is likely temporary; the operation may be retried after a delay.
    Transient,
    /// The error is permanent; retrying would not help.
    Fatal,
}

/// A bounded, zero-knowledge detail for a failure report. It is built only from vetted scalars
/// (status codes, exit codes, env var and error kind names), never an arbitrary `String`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafeDetail(String);

impl SafeDetail {
    /// Maximum byte length of a detail string (server contract).
    pub(crate) const MAX_LEN: usize = 500;

    /// Truncates `s` to at most [`Self::MAX_LEN`] bytes, on a char boundary.
    fn truncate(s: String) -> String {
        if s.len() <= Self::MAX_LEN {
            s
        } else {
            let mut end = Self::MAX_LEN;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            // `end` is a char boundary, so `get` returns Some.
            s.get(..end).unwrap_or_default().to_owned()
        }
    }

    #[cfg(test)]
    pub(crate) fn from_status(status: u16) -> Self {
        Self(Self::truncate(format!("HTTP {status}")))
    }

    pub(crate) fn from_exit_code(code: i32) -> Self {
        Self(Self::truncate(format!("exit code {code}")))
    }

    /// The signal number of a script ended by a signal.
    pub(crate) fn from_signal(signal: i32) -> Self {
        Self(Self::truncate(format!("signal {signal}")))
    }

    /// Variable names are safe to report; values never are.
    pub(crate) fn from_missing_vars(names: &[String]) -> Self {
        let joined = names.join(", ");
        Self(Self::truncate(format!("missing vars: {joined}")))
    }

    /// `kind` is a `'static` constant such as `"GraphRequest"`, never user-supplied input.
    pub(crate) fn from_kind(kind: &'static str) -> Self {
        Self(Self::truncate(format!("error kind: {kind}")))
    }

    pub(crate) fn timed_out(secs: u64) -> Self {
        Self(Self::truncate(format!("timed out after {secs}s")))
    }

    /// `reason` is a `'static` constant naming the failed check, never a value from the claim or
    /// blobs.
    pub(crate) fn from_seal_rejection(reason: &'static str) -> Self {
        Self(Self::truncate(format!("sealed data rejected: {reason}")))
    }

    /// Never includes Graph's `error.message`, which can echo user-supplied content.
    pub(crate) fn from_http_status_and_graph_code(status: u16, graph_code: Option<&str>) -> Self {
        let s = match graph_code {
            Some(code) => format!("HTTP {status} ({code})"),
            None => format!("HTTP {status}"),
        };
        Self(Self::truncate(s))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

// Safe to log, since the content is vetted at construction.
impl std::fmt::Display for SafeDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Startup errors, printed to stderr with a non-zero exit code. No `#[bitwarden_error]`, since the
/// connector has no language bindings.
#[derive(Debug, Error)]
pub enum AccessConnectorError {
    /// The configuration supplied is invalid, such as a missing URL or an out-of-range interval.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The access connector token string could not be parsed.
    #[error("invalid access connector token: {0}")]
    InvalidToken(String),

    /// The identity server could not be reached during startup authentication.
    #[error("identity server unreachable: {0}")]
    IdentityUnreachable(String),

    /// The access connector credential was rejected by the identity server.
    #[error("credential refused by identity server: {0}")]
    CredentialRefused(String),

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn safe_detail_from_signal() {
        let d = SafeDetail::from_signal(9);
        assert_eq!(d.as_str(), "signal 9");
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
    fn safe_detail_from_seal_rejection() {
        let d = SafeDetail::from_seal_rejection("target_method_not_automatic");
        assert_eq!(
            d.as_str(),
            "sealed data rejected: target_method_not_automatic"
        );
    }

    #[test]
    fn safe_detail_timed_out() {
        let d = SafeDetail::timed_out(60);
        assert_eq!(d.as_str(), "timed out after 60s");
    }

    #[test]
    fn safe_detail_truncated_at_500_chars() {
        // ASCII-only, so char length equals byte length.
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
        // Every constructor adds a prefix, so call truncate directly.
        let d = SafeDetail(SafeDetail::truncate(exactly.clone()));
        assert_eq!(d.as_str().len(), 500);
    }

    #[test]
    fn safe_detail_truncation_respects_char_boundary() {
        // The 500-byte mark falls inside a 2-byte é.
        let base = "a".repeat(499);
        let long = base + &"é".repeat(10);
        let d = SafeDetail(SafeDetail::truncate(long));
        assert!(
            d.as_str().len() <= SafeDetail::MAX_LEN,
            "truncated string must not exceed MAX_LEN bytes"
        );
        assert!(std::str::from_utf8(d.as_str().as_bytes()).is_ok());
    }
}
