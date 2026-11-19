//! 1Password importer.
//!
//! [`access`] is the Bitwarden-agnostic client that logs in and downloads the vaults.
//! [`convert`] maps what it returns onto the importer's parsed shape.

pub(crate) mod access;
pub(crate) mod convert;

use access::OnePasswordError;

use crate::ImportError;

impl From<OnePasswordError> for ImportError {
    fn from(error: OnePasswordError) -> Self {
        match error {
            OnePasswordError::BadCredentials => ImportError::OnePasswordBadCredentials,
            OnePasswordError::InvalidEmail => ImportError::OnePasswordInvalidEmail,
            OnePasswordError::InvalidSignInAddress(_) => {
                ImportError::OnePasswordInvalidSignInAddress
            }
            OnePasswordError::InvalidAccountKey(_) => ImportError::OnePasswordInvalidSecretKey,
            OnePasswordError::TwoFactorRequired => ImportError::OnePasswordTwoFactorRequired,
            OnePasswordError::TwoFactorFailed => ImportError::OnePasswordTwoFactorFailed,
            OnePasswordError::Canceled => ImportError::OnePasswordCanceled,
            OnePasswordError::Denied => ImportError::OnePasswordDenied,
            OnePasswordError::VerificationCodeFailed => {
                ImportError::OnePasswordVerificationCodeFailed
            }
            OnePasswordError::Unsupported(what) => ImportError::OnePasswordUnsupported(what),
            OnePasswordError::Network(what) => ImportError::OnePasswordNetwork(what),
            // A payload that will not decrypt or parse is the same story to a user: the account
            // came back unreadable.
            OnePasswordError::Decryption | OnePasswordError::Parse => {
                ImportError::OnePasswordDecryption
            }
            // Nothing a user can act on, and not the network either. The detail is for the logs.
            OnePasswordError::NotFound => {
                ImportError::OnePasswordInternal("the account or vault was not found".to_string())
            }
            OnePasswordError::Internal(what) => ImportError::OnePasswordInternal(what),
            error @ OnePasswordError::UnexpectedStatus { .. } => {
                ImportError::OnePasswordInternal(error.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_transport_failure_is_a_network_error() {
        assert!(matches!(
            ImportError::from(OnePasswordError::Network("connection reset".into())),
            ImportError::OnePasswordNetwork(what) if what == "connection reset"
        ));
        assert!(matches!(
            ImportError::from(OnePasswordError::Internal("device enrollment timed out".into())),
            ImportError::OnePasswordInternal(what) if what == "device enrollment timed out"
        ));
        for error in [
            OnePasswordError::NotFound,
            OnePasswordError::UnexpectedStatus {
                endpoint: "v3/auth/start".into(),
                status: 500,
            },
        ] {
            assert!(matches!(
                ImportError::from(error),
                ImportError::OnePasswordInternal(_)
            ));
        }
    }
}
