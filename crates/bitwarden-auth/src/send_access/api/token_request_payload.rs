use serde::{Deserialize, Serialize};

use crate::{
    api::enums::{GrantType, Scope},
    send_access::{SendAccessCredentials, SendAccessTokenRequest},
};

/// Represents the shape of the credentials used in the send access token payload.
#[derive(Serialize, Debug)]
// untagged allows for different variants to be serialized without a type tag
// example: { "password_hash_b64": "example_hash" } instead of { "Password": { "password_hash_b64":
// "example_hash" } }
#[serde(untagged)]
pub(crate) enum SendAccessTokenPayloadCredentials {
    // Uses inline variant syntax for these as we don't need to reference them as independent
    // types elsewhere.
    #[expect(missing_docs)]
    Password { password_hash_b64: String },
    #[expect(missing_docs)]
    Email { email: String },
    #[expect(missing_docs)]
    EmailOtp { email: String, otp: String },
    /// Represents an anonymous request, which does not require credentials.
    Anonymous,
}

impl From<Option<SendAccessCredentials>> for SendAccessTokenPayloadCredentials {
    fn from(credentials: Option<SendAccessCredentials>) -> Self {
        match credentials {
            Some(SendAccessCredentials::Password(credentials)) => {
                SendAccessTokenPayloadCredentials::Password {
                    password_hash_b64: credentials.password_hash_b64,
                }
            }
            Some(SendAccessCredentials::Email(credentials)) => {
                SendAccessTokenPayloadCredentials::Email {
                    email: credentials.email,
                }
            }
            Some(SendAccessCredentials::EmailOtp(credentials)) => {
                SendAccessTokenPayloadCredentials::EmailOtp {
                    email: credentials.email,
                    otp: credentials.otp,
                }
            }
            None => SendAccessTokenPayloadCredentials::Anonymous,
        }
    }
}

/// Enum representing the type of client requesting a send access token.
/// Eventually, this could / should be merged with the existing `ClientType` enum
#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum SendAccessClientType {
    /// Represents a Send client.
    /// This is a standalone client that lives within the BW web app, but has no context of a BW
    /// user.
    #[serde(rename = "send")]
    Send,
}

/// Represents the actual request payload for requesting a send access token.
/// It converts the `SendAccessTokenRequest` into a format suitable for sending to the API.
#[derive(Serialize, Debug)]
pub(crate) struct SendAccessTokenRequestPayload {
    // Standard OAuth2 fields
    /// The client ID for the send access client.
    pub(crate) client_id: SendAccessClientType,

    /// The grant type for the send access token request.
    /// SendAccess is a custom grant type for send access tokens.
    /// It is used to differentiate send access requests from other OAuth2 flows.
    pub(crate) grant_type: GrantType,

    /// The scope for the send access token request.
    /// This is set to "api.send" to indicate that the token is for send access.
    /// It allows the token to be used for accessing send-related resources.
    pub(crate) scope: Scope,

    // Custom fields
    /// The ID of the send for which the access token is being requested.
    pub(crate) send_id: String,

    /// The credentials used for the send access request.
    /// This can be password, email, email OTP, or anonymous.
    // Flatten allows us to serialize the variant directly into the payload without a wrapper
    // example: { "password_hash_b64": "example_hash" } instead of { "variant": {
    // "password_hash_b64": "example_hash" } }
    #[serde(flatten)]
    pub(crate) credentials: SendAccessTokenPayloadCredentials,
}

const SEND_ACCESS_CLIENT_ID: SendAccessClientType = SendAccessClientType::Send;
const SEND_ACCESS_GRANT_TYPE: GrantType = GrantType::SendAccess;
const SEND_ACCESS_SCOPE: Scope = Scope::ApiSendAccess;

/// Implement a way to convert from our request model to the payload model
impl From<SendAccessTokenRequest> for SendAccessTokenRequestPayload {
    fn from(request: SendAccessTokenRequest) -> Self {
        // Returns a new instance of `SendAccessTokenPayload` based on the provided
        // `SendAccessTokenRequest`. It extracts the necessary fields from the request and
        // matches on the credentials to determine the variant
        SendAccessTokenRequestPayload {
            client_id: SEND_ACCESS_CLIENT_ID,
            grant_type: SEND_ACCESS_GRANT_TYPE,
            scope: SEND_ACCESS_SCOPE,
            send_id: request.send_id,
            credentials: request.send_access_credentials.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json;

    use super::*;

    /// Unit tests for `SendAccessTokenPayload` serialization
    mod send_access_token_payload_tests {
        use super::*;
        #[test]
        fn test_serialize_send_access_token_password_payload() {
            let payload = SendAccessTokenRequestPayload {
                client_id: SendAccessClientType::Send,
                grant_type: GrantType::SendAccess,
                scope: Scope::ApiSendAccess,
                send_id: "example_send_id".into(),
                credentials: SendAccessTokenPayloadCredentials::Password {
                    password_hash_b64: "example_hash".into(),
                },
            };

            let serialized = serde_json::to_string_pretty(&payload).unwrap();

            // Parse both sides to JSON values and compare structurally.
            let got: serde_json::Value = serde_json::from_str(&serialized).unwrap();
            let want = serde_json::json!({
                "client_id": "send",
                "grant_type": "send_access",
                "scope": "api.send.access",
                "send_id": "example_send_id",
                "password_hash_b64": "example_hash"
            });

            assert_eq!(got, want);
        }

        #[test]
        fn test_serialize_send_access_token_email_payload() {
            let payload = SendAccessTokenRequestPayload {
                client_id: SendAccessClientType::Send,
                grant_type: GrantType::SendAccess,
                scope: Scope::ApiSendAccess,
                send_id: "example_send_id".into(),
                credentials: SendAccessTokenPayloadCredentials::Email {
                    email: "example_email".into(),
                },
            };

            let serialized = serde_json::to_string_pretty(&payload).unwrap();

            // Parse both sides to JSON values and compare structurally.
            let got: serde_json::Value = serde_json::from_str(&serialized).unwrap();
            let want = serde_json::json!({
                "client_id": "send",
                "grant_type": "send_access",
                "scope": "api.send.access",
                "send_id": "example_send_id",
                "email": "example_email"
            });

            assert_eq!(got, want);
        }

        #[test]
        fn test_serialize_send_access_token_email_otp_payload() {
            let payload = SendAccessTokenRequestPayload {
                client_id: SendAccessClientType::Send,
                grant_type: GrantType::SendAccess,
                scope: Scope::ApiSendAccess,
                send_id: "example_send_id".into(),
                credentials: SendAccessTokenPayloadCredentials::EmailOtp {
                    email: "example_email".into(),
                    otp: "example_otp".into(),
                },
            };
            let serialized = serde_json::to_string_pretty(&payload).unwrap();
            // Parse both sides to JSON values and compare structurally.
            let got: serde_json::Value = serde_json::from_str(&serialized).unwrap();
            let want = serde_json::json!({
                "client_id": "send",
                "grant_type": "send_access",
                "scope": "api.send.access",
                "send_id": "example_send_id",
                "email": "example_email",
                "otp": "example_otp"
            });

            assert_eq!(got, want);
        }
    }
}
