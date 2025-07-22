use serde::Deserialize;

use crate::auth::send_access::responses::enums::{
    SendAccessTokenInvalidGrantError, SendAccessTokenInvalidRequestError,
};

#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(tag = "error", content = "error_description")]
// ^ "error" becomes the variant discriminator which matches against the rename annotations; "error_description" is the payload for that variant which can be optional.
/// Represents the possible errors that can occur when requesting a send access token.
pub enum SendAccessTokenError {
    #[serde(rename = "invalid_request")]
    /// Invalid request error, typically due to missing parameters for a specific
    /// credential flow. Ex. `send_id` is required.
    /// #[serde(default)] allows for inner error details to be optional.
    InvalidRequest(#[serde(default)] Option<SendAccessTokenInvalidRequestError>),

    /// Invalid grant error, typically due to invalid credentials.
    /// Ex. `Password_hash` is invalid.
    /// #[serde(default)] allows for inner error details to be optional.
    #[serde(rename = "invalid_grant")]
    InvalidGrant(#[serde(default)] Option<SendAccessTokenInvalidGrantError>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_send_access_token_error_invalid_request() {
        let obj = r#"{ "error": "invalid_request" }"#;
        let result: SendAccessTokenError = serde_json::from_str(obj).unwrap();
        assert_eq!(result, SendAccessTokenError::InvalidRequest(None));
    }

    #[test]
    fn test_deserialize_send_access_token_error_invalid_grant() {
        let obj = r#"{ "error": "invalid_grant" }"#;
        let result: SendAccessTokenError = serde_json::from_str(obj).unwrap();
        assert_eq!(result, SendAccessTokenError::InvalidGrant(None));
    }

    #[test]
    fn test_deserialize_send_access_token_error_invalid_request_with_details() {
        let obj = r#"{ "error": "invalid_request", "error_description": "send_id is required." }"#;
        let result: SendAccessTokenError = serde_json::from_str(obj).unwrap();
        assert_eq!(
            result,
            SendAccessTokenError::InvalidRequest(Some(
                SendAccessTokenInvalidRequestError::SendIdRequired
            ))
        );
    }

    #[test]
    fn test_deserialize_send_access_token_error_invalid_grant_with_details() {
        let obj = r#"{ "error": "invalid_grant", "error_description": "Password_hash invalid." }"#;
        let result: SendAccessTokenError = serde_json::from_str(obj).unwrap();
        assert_eq!(
            result,
            SendAccessTokenError::InvalidGrant(Some(
                SendAccessTokenInvalidGrantError::InvalidPasswordHash
            ))
        );
    }
}
