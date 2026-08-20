use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

/// Errors from decoding a PAM server response into a domain view.
///
/// This is shared by all three leasing clients because they decode the *same* payloads, not because
/// their operations are alike: [`ApprovalsClient`](crate::ApprovalsClient) and
/// [`LeasesClient::extend`](crate::LeasesClient::extend) both return
/// [`AccessRequestView`](crate::AccessRequestView)s, so a malformed access-request payload fails
/// identically whichever client asked for it. Each client wraps this in its own error type rather
/// than exposing it directly, so a caller only sees the failure modes its own call can produce.
#[derive(Debug, Error)]
pub enum PamDecodeError {
    /// The server response was missing a field required to build the requested type.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// The server returned an access-request decider kind this SDK version does not recognize.
    #[error("The server returned an unrecognized access-request decider kind")]
    UnrecognizedDeciderKind,
    /// A date field in the server response could not be parsed.
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
}

/// Errors from a PAM read - a list, a get, a pre-check.
///
/// Shared by every read on every PAM client, because a read has no failure of its own to report: it
/// either reaches the server and decodes, or it does not. The server refuses a read it must not
/// serve with a `404`, which carries no code, so there is nothing here for a caller to switch on
/// beyond "it did not work".
///
/// Write operations do not use this. Each returns its own enum naming exactly the failures that one
/// call can produce, so a caller matching on it is matching on a set the compiler agrees is
/// complete.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PamReadError {
    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(ApiError),
}

impl From<ApiError> for PamReadError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}
