//! Domain types produced by the [`super`] API wrapper; the wire DTOs come from
//! `bitwarden_api_api::models`.

use uuid::Uuid;

use crate::{auth::session::SessionLost, error::Retry};

/// A claimable rotation job returned by the poll endpoint.
#[derive(Debug, Clone)]
pub(crate) struct JobRef {
    pub(crate) id: Uuid,
}

/// Errors returned by the [`super::AccessConnectorClient`] wrapper. They never include response
/// bodies, which can contain sensitive data.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    /// The connector's session was terminally lost (revoked or closed).
    #[error("session lost: {0:?}")]
    SessionLost(SessionLost),

    /// The server returned 409. A claim maps it to `Ok(None)` instead.
    #[error("rejected (HTTP {status})")]
    Rejected {
        /// The HTTP status, typically 409.
        status: u16,
    },

    /// A 404 on an attempt-scoped route: the server does not know the attempt, so it should be
    /// abandoned unreported.
    #[error("attempt not found (404)")]
    UnknownAttempt,

    /// A 404 on a connector or job route: the server does not consider this connector eligible.
    #[error("access connector not eligible (404 on connector route)")]
    NotEligible,

    /// A transport error, 429, 5xx, a 401 that survived the refresh retry, or any other unexpected
    /// status. The message is a bounded status or error kind, never body content.
    #[error("transient error: {0}")]
    Transient(String),

    /// The response could not be decoded or lacked a required field.
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl ApiError {
    /// Only a transient error is worth retrying.
    pub(crate) fn retry_class(&self) -> Retry {
        match self {
            ApiError::Transient(_) => Retry::Transient,
            _ => Retry::Permanent,
        }
    }
}
