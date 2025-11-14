use serde::{Deserialize, Serialize};

/// Represents the OAuth 2.0 grant types recognized by the Bitwarden API.
/// A grant type specifies the method a client uses to obtain an access token,
/// as defined in [RFC 6749, Section 4](https://datatracker.ietf.org/doc/html/rfc6749#section-4)
/// or by custom Bitwarden extensions. The value is sent in the `grant_type` parameter
/// of a token request.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GrantType {
    /// A custom extension grant type for requesting send access tokens outside the context of a
    /// Bitwarden user.
    SendAccess,
    // TODO: Add other grant types as needed.
    Password,
}
