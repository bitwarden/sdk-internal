//! User unlock / crypto initialization for the Bitwarden SDK.
//!
//! This crate contains the "unlock path" — the code responsible for
//! initialising a user's cryptographic state from one of the supported
//! methods (master password, PIN, device key, key-connector, etc.).

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

#[cfg(feature = "internal")]
pub use bitwarden_core::key_management::{
    MasterPasswordAuthenticationData, MasterPasswordError, MasterPasswordUnlockData, PinLockSystem,
    PinLockType, PinUnlockStatus, V2UpgradeToken, V2UpgradeTokenError,
    account_cryptographic_state::WrappedAccountCryptographicState,
    crypto::{
        AuthRequestMethod, InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest,
        initialize_org_crypto, initialize_user_crypto,
    },
};
