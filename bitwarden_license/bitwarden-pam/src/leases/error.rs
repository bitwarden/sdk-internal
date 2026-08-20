//! Each write on the lease surface names the failures that one call can produce. The sets come
//! from the server: `RequestLeaseExtensionCommand` backs [`extend`](super::LeasesClient::extend)
//! and `RevokeAccessLeaseCommand` backs [`end`](super::LeasesClient::end), so the `from_code`
//! tables below are transcribed from those rather than inferred.
//!
//! The two list calls use [`PamReadError`](crate::PamReadError).
//! [`leased_cipher`](super::LeasesClient::leased_cipher) is the one call that reads a vault payload
//! rather than a leasing one, so it has its own error naming the crypto failures the others cannot
//! produce.
//!
//! A code this SDK version does not recognize stays `Api` on every one of these, so a server that
//! grows a code never needs a client release to be safe.

use bitwarden_core::ApiError;
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_vault::VaultParseError;
use thiserror::Error;

use crate::{error::PamDecodeError, problem};

/// Errors from [`LeasesClient::extend`](super::LeasesClient::extend).
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessLeaseExtendError {
    /// The lease has ended - revoked, cancelled or lapsed - so there is nothing to extend.
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

    /// A server response could not be decoded into the requested type. Extending returns the
    /// updated [`AccessRequestView`](crate::AccessRequestView), so it decodes a request payload.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server, or the server
    /// refused with a code this SDK version does not recognize.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessLeaseExtendError {
    /// The codes `RequestLeaseExtensionCommand` can return.
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

impl From<ApiError> for AccessLeaseExtendError {
    fn from(error: ApiError) -> Self {
        problem::classify(&error, Self::from_code).unwrap_or(Self::Api(error))
    }
}

/// Errors from [`LeasesClient::end`](super::LeasesClient::end).
///
/// Ending a lease decodes nothing and has one refusal: the lease was not active to begin with.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessLeaseEndError {
    /// The lease has ended - revoked, cancelled or lapsed - so there is nothing to end.
    #[error("This lease is no longer active")]
    NotActive,

    /// A network or (de)serialization error occurred while calling the server, or the server
    /// refused with a code this SDK version does not recognize.
    #[error(transparent)]
    Api(ApiError),
}

impl AccessLeaseEndError {
    /// The codes `RevokeAccessLeaseCommand` can return. `access_lease_not_active` is the one code
    /// the server deliberately shares between ending and extending - the same condition reached
    /// from two endpoints - so it appears here and on
    /// [`AccessLeaseExtendError`](AccessLeaseExtendError::NotActive) both.
    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "access_lease_not_active" => Self::NotActive,
            _ => return None,
        })
    }
}

impl From<ApiError> for AccessLeaseEndError {
    fn from(error: ApiError) -> Self {
        problem::classify(&error, Self::from_code).unwrap_or(Self::Api(error))
    }
}

/// Errors from [`LeasesClient::leased_cipher`](super::LeasesClient::leased_cipher).
///
/// The one PAM call that decrypts a vault payload, so it is the only one that can fail on crypto.
/// The server refuses a cipher the lease does not cover with a `404`, which carries no code.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum LeasedCipherError {
    /// A cipher payload could not be parsed into the SDK's vault model.
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    /// A leased cipher could not be decrypted.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A server response could not be decoded into the requested type.
    #[error(transparent)]
    Decode(#[from] PamDecodeError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(ApiError),
}

impl From<ApiError> for LeasedCipherError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
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
        let error: AccessLeaseExtendError = problem("extension_exceeds_max").into();

        assert!(matches!(error, AccessLeaseExtendError::ExtensionExceedsMax));
    }

    #[test]
    fn a_code_shared_with_the_request_surface_maps_to_this_calls_variant() {
        // `duration_must_be_positive` means the same thing wherever it is raised, so both calls
        // name it - each in its own enum, because a caller only sees the failures its call can
        // make.
        let error: AccessLeaseExtendError = problem("duration_must_be_positive").into();

        assert!(matches!(
            error,
            AccessLeaseExtendError::DurationMustBePositive
        ));
    }

    #[test]
    fn the_shared_not_active_code_is_named_by_both_lease_writes() {
        let extending: AccessLeaseExtendError = problem("access_lease_not_active").into();
        let ending: AccessLeaseEndError = problem("access_lease_not_active").into();

        assert!(matches!(extending, AccessLeaseExtendError::NotActive));
        assert!(matches!(ending, AccessLeaseEndError::NotActive));
    }

    /// Ending a lease cannot produce an extension's refusals, so its classifier must not name them.
    #[test]
    fn ending_does_not_classify_an_extension_code() {
        let error: AccessLeaseEndError = problem("extension_exceeds_max").into();

        assert!(matches!(error, AccessLeaseEndError::Api(_)));
    }

    #[test]
    fn an_unrecognized_code_stays_untyped() {
        let error: AccessLeaseExtendError = problem("invented_next_year").into();

        assert!(matches!(error, AccessLeaseExtendError::Api(_)));
    }
}
