use bitwarden_core::MissingFieldError;
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
