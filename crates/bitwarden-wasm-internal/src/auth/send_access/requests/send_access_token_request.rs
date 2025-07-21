/// Go to parent and import the necessary modules.
use super::super::requests::enums::SendAccessCredentials;

/// A request structure for requesting a send access token from the API.

// TODO: figure out if I will need to use serde to expose this outside the crate
// to the typescript layer.
// Note: deny_unknown_fields instructs serde to error if any unknown fields are present in the JSON.
// #[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendAccessTokenRequest {
    /// The id of the send for which the access token is requested.
    pub send_id: String,

    /// The optional send access credentials.
    pub send_access_credentials: Option<SendAccessCredentials>,
}
