use super::super::enums::SendAccessClientType;
use super::super::enums::SendAccessTokenPayloadVariant;
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct SendAccessTokenPayload {
    // Standard OAuth2 fields
    pub client_id: SendAccessClientType,
    pub grant_type: String,
    pub scope: String,

    // Custom fields
    pub send_id: String,
    // This allows us to serialize the variant directly into the payload without a wrapper
    // example: { "password_hash": "example_hash" } instead of { "variant": { "password_hash": "example_hash" } }
    #[serde(flatten)]
    pub variant: SendAccessTokenPayloadVariant,
}

/// Unit tests for `SendAccessTokenPayload` serialization
#[cfg(test)]
mod tests {
    use super::super::super::enums::SendAccessClientType;
    use super::super::super::enums::SendAccessTokenPayloadVariant;
    use super::SendAccessTokenPayload;
    use serde_json;

    #[test]
    fn test_serialize_send_access_token_payload() {
        let payload = SendAccessTokenPayload {
            client_id: SendAccessClientType::Send,
            grant_type: "password".into(),
            scope: "send_access".into(),
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
  "grant_type": "password",
  "scope": "send_access",
  "send_id": "example_send_id",
  "password_hash": "example_hash"
}"#
        );
    }
}
