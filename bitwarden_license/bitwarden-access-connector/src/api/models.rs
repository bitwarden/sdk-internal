//! Domain types produced by the [`super`] API wrapper; the wire DTOs come from
//! `bitwarden_api_api::models`.

use uuid::Uuid;

use crate::auth::session::SessionLost;

/// A claimable rotation job returned by the poll endpoint.
#[derive(Debug, Clone)]
pub(crate) struct JobRef {
    pub(crate) id: Uuid,
}

/// Errors returned by the [`super::AccessConnectorClient`] wrapper. They never include response
/// bodies, which can contain sensitive data.
#[derive(Debug)]
pub(crate) enum ApiError {
    /// The connector's session was terminally lost (revoked or closed).
    SessionLost(SessionLost),

    /// The server returned 409. A claim maps it to `Ok(None)` instead; on a cipher write it means
    /// revision drift or capability lost.
    Rejected {
        /// The HTTP status, typically 409.
        status: u16,
    },

    /// A 404 on an attempt-scoped route (`/cipher`, `/success`, `/failure`): the server does not
    /// know the attempt, so the executor abandons it unreported.
    UnknownAttempt,

    /// A 404 on a connector or job route: the server does not consider this connector eligible. The
    /// executor runs a refresh probe to tell this apart from `CredentialRefused`.
    NotEligible,

    /// A transport error, 429, 5xx, a 401 that survived the refresh retry, or any other unexpected
    /// status. The message is a bounded status or error kind, never body content.
    Transient(String),

    /// The response could not be decoded or lacked a required field. The message never includes
    /// payload content.
    Protocol(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionLost(l) => write!(f, "session lost: {l:?}"),
            Self::Rejected { status } => write!(f, "rejected (HTTP {status})"),
            Self::UnknownAttempt => write!(f, "attempt not found (404)"),
            Self::NotEligible => {
                write!(f, "access connector not eligible (404 on connector route)")
            }
            Self::Transient(s) => write!(f, "transient error: {s}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
        }
    }
}
