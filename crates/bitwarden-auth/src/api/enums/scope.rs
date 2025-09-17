use serde::{Deserialize, Serialize};

/// The OAuth 2.0 scopes recognized by the Bitwarden API.
/// Scopes define the specific permissions an access token grants to the client.
/// They are requested by the client during token acquisition and enforced by the
/// resource server when the token is used.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum Scope {
    /// The scope for accessing send resources outside the context of a Bitwarden user.
    #[serde(rename = "api.send.access")]
    ApiSendAccess,
    // TODO: Add other scopes as needed.
}
