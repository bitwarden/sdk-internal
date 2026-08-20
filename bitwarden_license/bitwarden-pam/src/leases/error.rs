use bitwarden_core::ApiError;
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_vault::VaultParseError;
use thiserror::Error;

use crate::{error::PamDecodeError, problem};

/// Errors returned from [`super::LeasesClient`] operations.
///
/// The lease surface has no local validation and no write-side enum narrowing, so it mostly carries
/// the decode and transport variants every PAM call can produce. It decodes access-request payloads
/// as well as lease payloads, because [`extend`](super::LeasesClient::extend) returns the updated
/// [`AccessRequestView`](crate::AccessRequestView).
///
/// [`VaultParse`](Self::VaultParse) and [`Crypto`](Self::Crypto) are reachable only from
/// [`leased_cipher`](super::LeasesClient::leased_cipher), the one call that reads a vault payload
/// rather than a leasing one.
///
/// The named server failures each correspond to one stable code in the server's problem response;
/// see [`from_code`](Self::from_code) for the mapping. A code this SDK version does not recognize
/// stays [`Api`](Self::Api), so a server that grows one never needs a client release to be safe.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessLeaseError {
    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// The lease has ended - revoked, cancelled or lapsed - so there is nothing to extend or end.
    #[error("This lease is no longer active")]
    NotActive,
    /// No access rule governs the cipher any more, and an extension reuses the cipher's governing
    /// rule.
    #[error("This item does not require a lease")]
    CipherNotGated,
    /// The cipher's governing rule does not opt in to extensions.
    #[error("This item does not allow extending a lease")]
    ExtensionsNotAllowed,
    /// The requested extension is absent, zero or negative.
    #[error("A positive duration is required")]
    DurationMustBePositive,
    /// The requested extension is longer than the governing rule's maximum extension length.
    #[error("The requested duration exceeds the maximum extension length for this item")]
    ExtensionExceedsMax,
    /// An extension is recorded against the audit trail, so it has to say why it was taken.
    #[error("A justification is required to extend a lease")]
    ExtensionReasonRequired,
    /// A lease may be extended exactly once, and this one already has been.
    #[error("This lease has already been extended")]
    AlreadyExtended,

    /// A cipher payload could not be parsed into the SDK's vault model.
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    /// A leased cipher could not be decrypted.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A network or (de)serialization error occurred while calling the server, or the server
    /// refused with a code this SDK version does not recognize.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessLeaseError {
    /// The server's codes, in the order the lease surface can produce them.
    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "access_lease_not_active" => Self::NotActive,
            "cipher_not_gated" => Self::CipherNotGated,
            "extensions_not_allowed" => Self::ExtensionsNotAllowed,
            "duration_must_be_positive" => Self::DurationMustBePositive,
            "extension_exceeds_max" => Self::ExtensionExceedsMax,
            "extension_reason_required" => Self::ExtensionReasonRequired,
            "access_lease_already_extended" => Self::AlreadyExtended,
            _ => return None,
        })
    }
}

/// Classifies every failed call on this surface, so a caller gets the typed variant whichever
/// method it came from.
impl From<ApiError> for AccessLeaseError {
    fn from(error: ApiError) -> Self {
        problem::classify(&error, Self::from_code).unwrap_or(Self::Api(error))
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::ResponseContent;
    use reqwest::StatusCode;

    use super::*;

    fn problem(code: &str) -> ApiError {
        ApiError::Response(ResponseContent {
            status: StatusCode::BAD_REQUEST,
            message: format!(r#"{{"errors":{{"code":[{{"type":"{code}"}}]}}}}"#),
        })
    }

    #[test]
    fn an_extension_failure_becomes_its_own_variant() {
        let error: AccessLeaseError = problem("extension_exceeds_max").into();

        assert!(matches!(error, AccessLeaseError::ExtensionExceedsMax));
    }

    #[test]
    fn a_code_shared_with_the_request_surface_maps_to_this_surfaces_variant() {
        // `duration_must_be_positive` means the same thing wherever it is raised, so both surfaces
        // name it - each in its own enum, because a caller only sees the failures its call can
        // make.
        let error: AccessLeaseError = problem("duration_must_be_positive").into();

        assert!(matches!(error, AccessLeaseError::DurationMustBePositive));
    }

    #[test]
    fn an_unrecognized_code_stays_untyped() {
        let error: AccessLeaseError = problem("invented_next_year").into();

        assert!(matches!(error, AccessLeaseError::Api(_)));
    }
}
