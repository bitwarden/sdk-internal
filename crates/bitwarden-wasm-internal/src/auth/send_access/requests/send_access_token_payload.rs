use crate::auth::send_access::requests::{
    enums::{SendAccessClientType, SendAccessTokenPayloadVariant},
    SendAccessTokenRequest,
};

use super::super::super::common::enums::{GrantType, Scope};

use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct SendAccessTokenPayload {
    // Standard OAuth2 fields
    pub client_id: SendAccessClientType,
    pub grant_type: GrantType,
    pub scope: Scope,

    // Custom fields
    pub send_id: String,
    // This allows us to serialize the variant directly into the payload without a wrapper
    // example: { "password_hash": "example_hash" } instead of { "variant": { "password_hash": "example_hash" } }
    #[serde(flatten)]
    pub variant: SendAccessTokenPayloadVariant,
}

const SEND_ACCESS_CLIENT_ID: SendAccessClientType = SendAccessClientType::Send;
const SEND_ACCESS_GRANT_TYPE: GrantType = GrantType::SendAccess;
const SEND_ACCESS_SCOPE: Scope = Scope::Send;

// Rust has into and from traits for easy conversion between types. If you implement from then rust will automatically implement into for you.
// We want to implement from SendAccessTokenRequest to the SendAccessTokenPayload struct.
// we are going to implement a from method to convert SendAccessTokenRequest to SendAccessTokenPayload
impl From<SendAccessTokenRequest> for SendAccessTokenPayload {
    fn from(request: SendAccessTokenRequest) -> Self {
        // Returns a new instance of `SendAccessTokenPayload` based on the provided `SendAccessTokenRequest`.
        // It extracts the necessary fields from the request and matches on the credentials to determine the variant
        SendAccessTokenPayload {
            client_id: SEND_ACCESS_CLIENT_ID,
            grant_type: SEND_ACCESS_GRANT_TYPE,
            scope: SEND_ACCESS_SCOPE,
            send_id: request.send_id,
            variant: request.send_access_credentials.into(),
        }
    }
}

/// Unit tests for `SendAccessTokenPayload` serialization
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_serialize_send_access_token_payload() {
        let payload = SendAccessTokenPayload {
            client_id: SendAccessClientType::Send,
            grant_type: GrantType::SendAccess,
            scope: Scope::Send,
            send_id: "example_send_id".into(),
            variant: SendAccessTokenPayloadVariant::Password {
                password_hash: "example_hash".into(),
            },
        };

        let serialized = serde_json::to_string_pretty(&payload).unwrap();
        println!("{}", serialized);
        assert_eq!(
            serialized,
            r#"{
  "client_id": "send",
  "grant_type": "send_access",
  "scope": "api.send",
  "send_id": "example_send_id",
  "password_hash": "example_hash"
}"#
        );
    }
}
