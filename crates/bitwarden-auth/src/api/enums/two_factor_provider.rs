use serde_repr::{Deserialize_repr, Serialize_repr};

// TODO: This likely won't be limited to just API usage so consider moving to a more general
// location when implementing 2FA support

/// Represents the two-factor authentication providers supported by Bitwarden.
#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone)]
#[repr(u8)]
pub enum TwoFactorProvider {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}
