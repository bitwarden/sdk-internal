//! Names of the Chrome DevTools performance tracks this module draws on.
//!
//! ```text
//!   ── Key Management ───────────────────────────
//!       User crypto           ▉▉▉▉▉▉▉▉▉▉        ◀ one entry per unlock
//!       Organization crypto        ▉▉           ◀ one entry per org key import
//! ```
//!
//! An unlock spans every step of initializing the user's cryptographic state, so the key
//! derivation it triggers — drawn on the `Slow Crypto` group by `bitwarden-crypto` — lines up
//! underneath it, showing how much of an unlock is the KDF and how much is everything else.

use crate::key_management::crypto::InitUserCryptoMethod;

/// Track group holding the initialization of a user's cryptographic state.
pub(crate) const GROUP: &str = "Key Management";

/// Unlocks, by the factor they were performed with.
pub(crate) const USER_CRYPTO_TRACK: &str = "User crypto";

/// Imports of the keys of the organizations a user belongs to.
pub(crate) const ORG_CRYPTO_TRACK: &str = "Organization crypto";

/// Names the unlock factor, which is what decides how expensive an unlock is. Deliberately only
/// the variant: the payloads carry key material.
pub(crate) fn method_name(method: &InitUserCryptoMethod) -> &'static str {
    match method {
        InitUserCryptoMethod::MasterPasswordUnlock { .. } => "master password",
        InitUserCryptoMethod::ClientManagedState { .. } => "client managed state",
        InitUserCryptoMethod::DecryptedKey { .. } => "decrypted key",
        InitUserCryptoMethod::Pin { .. } => "PIN",
        InitUserCryptoMethod::PinState { .. } => "PIN state",
        InitUserCryptoMethod::PinEnvelope { .. } => "PIN envelope",
        InitUserCryptoMethod::AuthRequest { .. } => "auth request",
        InitUserCryptoMethod::DeviceKey { .. } => "device key",
        InitUserCryptoMethod::KeyConnector { .. } => "key connector",
        InitUserCryptoMethod::KeyConnectorUrl { .. } => "key connector URL",
    }
}
