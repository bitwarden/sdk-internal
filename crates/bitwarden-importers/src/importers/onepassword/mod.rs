//! 1Password importer.
//!
//! [`access`] is the Bitwarden-agnostic client that logs in and downloads the vaults.
//! [`convert`] maps what it returns onto the importer's parsed shape.

// Both are `pub` for the `test-utils` re-export.
// TODO: Make them `pub(crate)` once the out-of-tree CLI is retired.
pub mod access;
pub mod convert;

use access::OnePasswordError;

use crate::ImportError;

impl From<OnePasswordError> for ImportError {
    fn from(error: OnePasswordError) -> Self {
        match error {
            OnePasswordError::BadCredentials => ImportError::OnePasswordBadCredentials,
            OnePasswordError::InvalidSignInAddress(_) => {
                ImportError::OnePasswordInvalidSignInAddress
            }
            OnePasswordError::TwoFactorRequired => ImportError::OnePasswordTwoFactorRequired,
            OnePasswordError::TwoFactorFailed => ImportError::OnePasswordTwoFactorFailed,
            OnePasswordError::Unsupported(what) => ImportError::OnePasswordUnsupported(what),
            OnePasswordError::Network(what) => ImportError::OnePasswordNetwork(what),
            // A payload that will not decrypt or parse is the same story to a user: the account
            // came back unreadable.
            OnePasswordError::Decryption | OnePasswordError::Parse => {
                ImportError::OnePasswordDecryption
            }
            // Neither of these can reach a caller as anything actionable, so they read as a
            // transport failure with the detail kept.
            OnePasswordError::NotFound => {
                ImportError::OnePasswordNetwork("the account or vault was not found".to_string())
            }
            OnePasswordError::Internal(what) => ImportError::OnePasswordNetwork(what),
        }
    }
}
