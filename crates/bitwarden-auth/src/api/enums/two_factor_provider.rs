use schemars::JsonSchema;
use serde_repr::{Deserialize_repr, Serialize_repr};

// TODO: this isn't likely to be only limited to API usage... so maybe move to a more general
// location?

/// Represents the two-factor authentication providers supported by Bitwarden.
#[allow(missing_docs)]
#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, JsonSchema, Clone)]
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
