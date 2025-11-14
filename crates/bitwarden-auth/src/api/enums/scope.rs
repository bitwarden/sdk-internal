use serde::{Deserialize, Serialize};

/// The OAuth 2.0 scopes recognized by the Bitwarden API.
/// Scopes define the specific permissions an access token grants to the client.
/// They are requested by the client during token acquisition and enforced by the
/// resource server when the token is used.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The scope for accessing the Bitwarden API.
    #[serde(rename = "api")]
    Api,
    /// The scope for obtaining refresh tokens that allow offline access.
    #[serde(rename = "offline_access")]
    OfflineAccess,
    /// The scope for accessing send resources outside the context of a Bitwarden user.
    #[serde(rename = "api.send.access")]
    ApiSendAccess,
}

impl Scope {
    /// Returns the string representation of the scope as used in OAuth 2.0 requests.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Scope::Api => "api",
            Scope::OfflineAccess => "offline_access",
            Scope::ApiSendAccess => "api.send.access",
        }
    }
}

/// Converts a slice of scopes into a space-separated string suitable for OAuth 2.0 requests.
pub(crate) fn scopes_to_string(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}
