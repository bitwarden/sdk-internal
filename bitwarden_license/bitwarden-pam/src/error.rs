use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

/// Errors returned from the PAM leasing clients
/// ([`AccessRequestsClient`](crate::AccessRequestsClient),
/// [`LeasesClient`](crate::LeasesClient), and [`ApprovalsClient`](crate::ApprovalsClient)).
///
/// Access requests, leases, and approvals are facets of the same lifecycle - activating a request
/// mints a lease, extending a lease returns the updated request, and deciding a request is the
/// approver-side counterpart of submitting one - so all three clients share one error type rather
/// than each defining a near-identical one.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum LeasingError {
    /// The server response was missing a field required to build the requested type.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// The server returned an access-request decider kind this SDK version does not recognize.
    #[error("The server returned an unrecognized access-request decider kind")]
    UnrecognizedDeciderKind,
    /// A decision was submitted with a verdict this SDK cannot put on the wire. `Unknown` is a
    /// read-side spelling for a verdict a newer server returned, never something to submit.
    #[error("An access-request decision cannot be submitted with an unrecognized verdict")]
    UnsubmittableVerdict,
    /// A date field in the server response could not be parsed.
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}
