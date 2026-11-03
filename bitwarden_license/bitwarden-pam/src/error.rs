use bitwarden_core::MissingFieldError;
use thiserror::Error;

/// Errors from decoding a PAM server response into a domain view.
///
/// Shared by the access request, approval and lease clients, which each wrap it in their own
/// error type.
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
