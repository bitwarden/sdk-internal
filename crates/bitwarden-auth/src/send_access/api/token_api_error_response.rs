use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
/// Invalid request errors - typically due to missing parameters.
pub enum SendAccessTokenInvalidRequestError {
    #[allow(missing_docs)]
    SendIdRequired,

    #[allow(missing_docs)]
    PasswordHashB64Required,

    #[allow(missing_docs)]
    EmailRequired,

    #[allow(missing_docs)]
    EmailAndOtpRequiredOtpSent,

    /// Fallback for unknown variants for forward compatibility
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
/// Invalid grant errors - typically due to invalid credentials.
pub enum SendAccessTokenInvalidGrantError {
    #[allow(missing_docs)]
    SendIdInvalid,

    #[allow(missing_docs)]
    PasswordHashB64Invalid,

    #[allow(missing_docs)]
    EmailInvalid,

    #[allow(missing_docs)]
    OtpInvalid,

    #[allow(missing_docs)]
    OtpGenerationFailed,

    /// Fallback for unknown variants for forward compatibility
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
#[serde(tag = "error")]
// ^ "error" becomes the variant discriminator which matches against the rename annotations;
// "error_description" is the payload for that variant which can be optional.
/// Represents the possible, expected errors that can occur when requesting a send access token.
pub enum SendAccessTokenApiErrorResponse {
    /// Invalid request error, typically due to missing parameters for a specific
    /// credential flow. Ex. `send_id` is required.
    InvalidRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid request errors.
        error_description: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional specific error type for invalid request errors.
        send_access_error_type: Option<SendAccessTokenInvalidRequestError>,
    },

    /// Invalid grant error, typically due to invalid credentials.
    InvalidGrant {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid grant errors.
        error_description: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional specific error type for invalid grant errors.
        send_access_error_type: Option<SendAccessTokenInvalidGrantError>,
    },

    /// Invalid client error, typically due to an invalid client secret or client ID.
    InvalidClient {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid client errors.
        error_description: Option<String>,
    },

    /// Unauthorized client error, typically due to an unauthorized client.
    UnauthorizedClient {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for unauthorized client errors.
        error_description: Option<String>,
    },

    /// Unsupported grant type error, typically due to an unsupported credential flow.
    /// Note: during initial feature rollout, this will be used to indicate that the
    /// feature flag is disabled.
    UnsupportedGrantType {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for unsupported grant type errors.
        error_description: Option<String>,
    },

    /// Invalid scope error, typically due to an invalid scope requested.
    InvalidScope {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid scope errors.
        error_description: Option<String>,
    },

    /// Invalid target error which is shown if the requested
    /// resource is invalid, missing, unknown, or malformed.
    InvalidTarget {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid target errors.
        error_description: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    mod send_access_token_invalid_request_error_tests {
        use serde_json::{Value, from_str, json, to_string, to_value};

        use super::*;

        #[test]
        fn invalid_request_variants_serde_tests() {
            // (expected_variant, send_access_error_type)
            let cases: &[(SendAccessTokenInvalidRequestError, &str)] = &[
                (
                    SendAccessTokenInvalidRequestError::SendIdRequired,
                    "\"send_id_required\"",
                ),
                (
                    SendAccessTokenInvalidRequestError::PasswordHashB64Required,
                    "\"password_hash_b64_required\"",
                ),
                (
                    SendAccessTokenInvalidRequestError::EmailRequired,
                    "\"email_required\"",
                ),
                (
                    SendAccessTokenInvalidRequestError::EmailAndOtpRequiredOtpSent,
                    "\"email_and_otp_required_otp_sent\"",
                ),
            ];

            for (expected_variant, send_access_error_type_json) in cases {
                // Deserialize from send_access_error_type to enum
                let error_from_send_access_error_type: SendAccessTokenInvalidRequestError =
                    from_str(send_access_error_type_json).unwrap();
                assert_eq!(
                    &error_from_send_access_error_type, expected_variant,
                    "send_access_error_type should map to the expected variant"
                );

                // Serializing enum -> JSON string containing send_access_error_type
                let json_from_variant = to_string(expected_variant).unwrap();
                assert_eq!(
                    json_from_variant, *send_access_error_type_json,
                    "serialization should emit the send_access_error_type_json"
                );

                // Type-safe check: to_value() → Value::String, then compare the
                // code; this avoids formatting/quoting concerns from to_string().
                let value_from_variant = to_value(expected_variant).unwrap();
                assert_eq!(
                    value_from_variant,
                    Value::String(send_access_error_type_json.trim_matches('"').to_string()),
                    "serialization as value should match json generated from enum"
                );

                // Round-trip: send_access_error_type -> enum -> send_access_error_type
                let round_tripped_code = to_string(&error_from_send_access_error_type).unwrap();
                assert_eq!(
                    round_tripped_code, *send_access_error_type_json,
                    "round-trip should preserve the send_access_error_type_json"
                );
            }
        }

        #[test]
        fn invalid_request_full_payload_with_both_fields_parses() {
            let payload = json!({
                "error": "invalid_request",
                "error_description": "send_id is required.",
                "send_access_error_type": "send_id_required"
            })
            .to_string();

            let parsed: SendAccessTokenApiErrorResponse = from_str(&payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidRequest {
                    error_description,
                    send_access_error_type,
                } => {
                    assert_eq!(error_description.as_deref(), Some("send_id is required."));
                    assert_eq!(
                        send_access_error_type,
                        Some(SendAccessTokenInvalidRequestError::SendIdRequired)
                    );
                }
                _ => panic!("expected invalid_request"),
            }
        }

        #[test]
        fn invalid_request_payload_without_description_is_allowed() {
            let payload = r#"
            {
                "error": "invalid_request",
                "send_access_error_type": "email_required"
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidRequest {
                    error_description,
                    send_access_error_type,
                } => {
                    assert!(error_description.is_none());
                    assert_eq!(
                        send_access_error_type,
                        Some(SendAccessTokenInvalidRequestError::EmailRequired)
                    );
                }
                _ => panic!("expected invalid_request"),
            }
        }

        #[test]
        fn invalid_request_unknown_code_maps_to_unknown() {
            let payload = r#"
            {
                "error": "invalid_request",
                "error_description": "something new",
                "send_access_error_type": "brand_new_code"
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidRequest {
                    error_description,
                    send_access_error_type,
                } => {
                    assert_eq!(error_description.as_deref(), Some("something new"));
                    assert_eq!(
                        send_access_error_type,
                        Some(SendAccessTokenInvalidRequestError::Unknown)
                    );
                }
                _ => panic!("expected invalid_request"),
            }
        }

        #[test]
        fn invalid_request_minimal_payload_is_allowed() {
            let payload = r#"{ "error": "invalid_request" }"#;
            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidRequest {
                    error_description,
                    send_access_error_type,
                } => {
                    assert!(error_description.is_none());
                    assert!(send_access_error_type.is_none());
                }
                _ => panic!("expected invalid_request"),
            }
        }

        #[test]
        fn invalid_request_null_fields_become_none() {
            let payload = r#"
            {
                "error": "invalid_request",
                "error_description": null,
                "send_access_error_type": null
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidRequest {
                    error_description,
                    send_access_error_type,
                } => {
                    assert!(error_description.is_none());
                    assert!(send_access_error_type.is_none());
                }
                _ => panic!("expected invalid_request"),
            }
        }
    }

    mod send_access_token_invalid_grant_error_tests {
        use serde_json::{Value, from_str, json, to_string, to_value};

        use super::*;

        #[test]
        fn invalid_grant_variants_serde_tests() {
            // (expected_variant, send_access_error_type)
            let cases: &[(SendAccessTokenInvalidGrantError, &str)] = &[
                (
                    SendAccessTokenInvalidGrantError::SendIdInvalid,
                    "\"send_id_invalid\"",
                ),
                (
                    SendAccessTokenInvalidGrantError::PasswordHashB64Invalid,
                    "\"password_hash_b64_invalid\"",
                ),
                (
                    SendAccessTokenInvalidGrantError::EmailInvalid,
                    "\"email_invalid\"",
                ),
                (
                    SendAccessTokenInvalidGrantError::OtpInvalid,
                    "\"otp_invalid\"",
                ),
                (
                    SendAccessTokenInvalidGrantError::OtpGenerationFailed,
                    "\"otp_generation_failed\"",
                ),
            ];

            for (expected_variant, send_access_error_type_json) in cases {
                // Deserialize from send_access_error_type to enum
                let error_from_send_access_error_type: SendAccessTokenInvalidGrantError =
                    from_str(send_access_error_type_json).unwrap();
                assert_eq!(
                    &error_from_send_access_error_type, expected_variant,
                    "send_access_error_type should map to the expected variant"
                );

                // Serializing enum -> JSON string containing send_access_error_type
                let json_from_variant = to_string(expected_variant).unwrap();
                assert_eq!(
                    json_from_variant, *send_access_error_type_json,
                    "serialization should emit the send_access_error_type_json"
                );

                // Type-safe check: to_value() → Value::String
                let value_from_variant = to_value(expected_variant).unwrap();
                assert_eq!(
                    value_from_variant,
                    Value::String(send_access_error_type_json.trim_matches('"').to_string()),
                    "serialization as value should match json generated from enum"
                );

                // Round-trip: send_access_error_type -> enum -> send_access_error_type
                let round_tripped_code = to_string(&error_from_send_access_error_type).unwrap();
                assert_eq!(
                    round_tripped_code, *send_access_error_type_json,
                    "round-trip should preserve the send_access_error_type_json"
                );
            }
        }

        #[test]
        fn invalid_grant_full_payload_with_both_fields_parses() {
            let payload = json!({
                "error": "invalid_grant",
                "error_description": "password_hash_b64 is invalid.",
                "send_access_error_type": "password_hash_b64_invalid"
            })
            .to_string();

            let parsed: SendAccessTokenApiErrorResponse = from_str(&payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidGrant {
                    error_description,
                    send_access_error_type,
                } => {
                    assert_eq!(
                        error_description.as_deref(),
                        Some("password_hash_b64 is invalid.")
                    );
                    assert_eq!(
                        send_access_error_type,
                        Some(SendAccessTokenInvalidGrantError::PasswordHashB64Invalid)
                    );
                }
                _ => panic!("expected invalid_grant"),
            }
        }

        #[test]
        fn invalid_grant_payload_without_description_is_allowed() {
            let payload = r#"
            {
                "error": "invalid_grant",
                "send_access_error_type": "otp_invalid"
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidGrant {
                    error_description,
                    send_access_error_type,
                } => {
                    assert!(error_description.is_none());
                    assert_eq!(
                        send_access_error_type,
                        Some(SendAccessTokenInvalidGrantError::OtpInvalid)
                    );
                }
                _ => panic!("expected invalid_grant"),
            }
        }

        #[test]
        fn invalid_grant_unknown_code_maps_to_unknown() {
            let payload = r#"
            {
                "error": "invalid_grant",
                "error_description": "new server-side reason",
                "send_access_error_type": "brand_new_grant_code"
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidGrant {
                    error_description,
                    send_access_error_type,
                } => {
                    assert_eq!(error_description.as_deref(), Some("new server-side reason"));
                    assert_eq!(
                        send_access_error_type,
                        Some(SendAccessTokenInvalidGrantError::Unknown)
                    );
                }
                _ => panic!("expected invalid_grant"),
            }
        }

        #[test]
        fn invalid_grant_minimal_payload_is_allowed() {
            let payload = r#"{ "error": "invalid_grant" }"#;
            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidGrant {
                    error_description,
                    send_access_error_type,
                } => {
                    assert!(error_description.is_none());
                    assert!(send_access_error_type.is_none());
                }
                _ => panic!("expected invalid_grant"),
            }
        }

        #[test]
        fn invalid_grant_null_fields_become_none() {
            let payload = r#"
            {
                "error": "invalid_grant",
                "error_description": null,
                "send_access_error_type": null
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidGrant {
                    error_description,
                    send_access_error_type,
                } => {
                    assert!(error_description.is_none());
                    assert!(send_access_error_type.is_none());
                }
                _ => panic!("expected invalid_grant"),
            }
        }
    }

    mod send_access_token_invalid_client_error_tests {
        use serde_json::{from_str, json, to_value};

        use super::*;

        #[test]
        fn invalid_client_full_payload_with_description_parses() {
            let payload = json!({
                "error": "invalid_client",
                "error_description": "Invalid client credentials."
            })
            .to_string();

            let parsed: SendAccessTokenApiErrorResponse = from_str(&payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidClient { error_description } => {
                    assert_eq!(
                        error_description.as_deref(),
                        Some("Invalid client credentials.")
                    );
                }
                _ => panic!("expected invalid_client"),
            }
        }

        #[test]
        fn invalid_client_without_description_is_allowed() {
            let payload = r#"{ "error": "invalid_client" }"#;

            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidClient { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_client"),
            }
        }

        #[test]
        fn invalid_client_serializes_back() {
            let value = SendAccessTokenApiErrorResponse::InvalidClient {
                error_description: Some("Invalid client credentials.".into()),
            };
            let j = to_value(value).unwrap();
            assert_eq!(
                j,
                json!({
                    "error": "invalid_client",
                    "error_description": "Invalid client credentials."
                })
            );
        }

        #[test]
        fn invalid_client_minimal_payload_is_allowed() {
            let payload = r#"{ "error": "invalid_client" }"#;
            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidClient { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_client"),
            }
        }

        #[test]
        fn invalid_client_null_description_becomes_none() {
            let payload = r#"
            {
                "error": "invalid_client",
                "error_description": null
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidClient { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_client"),
            }
        }

        #[test]
        fn invalid_client_ignores_send_access_error_type_and_extra_fields() {
            let payload = r#"
            {
                "error": "invalid_client",
                "send_access_error_type": "should_be_ignored",
                "extra_field": 123,
                "error_description": "desc"
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidClient { error_description } => {
                    assert_eq!(error_description.as_deref(), Some("desc"));
                }
                _ => panic!("expected invalid_client"),
            }
        }
    }

    mod send_access_token_unauthorized_client_error_tests {
        use serde_json::{from_str, json, to_value};

        use super::*;

        #[test]
        fn unauthorized_client_full_payload_with_description_parses() {
            let payload = json!({
                "error": "unauthorized_client",
                "error_description": "Client not permitted to use this grant."
            })
            .to_string();

            let parsed: SendAccessTokenApiErrorResponse = from_str(&payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnauthorizedClient { error_description } => {
                    assert_eq!(
                        error_description.as_deref(),
                        Some("Client not permitted to use this grant.")
                    );
                }
                _ => panic!("expected unauthorized_client"),
            }
        }

        #[test]
        fn unauthorized_client_without_description_is_allowed() {
            let payload = r#"{ "error": "unauthorized_client" }"#;

            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnauthorizedClient { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected unauthorized_client"),
            }
        }

        #[test]
        fn unauthorized_client_serializes_back() {
            let value = SendAccessTokenApiErrorResponse::UnauthorizedClient {
                error_description: None,
            };
            let j = to_value(value).unwrap();
            assert_eq!(j, json!({ "error": "unauthorized_client" }));
        }

        #[test]
        fn unauthorized_client_minimal_payload_is_allowed() {
            let payload = r#"{ "error": "unauthorized_client" }"#;
            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnauthorizedClient { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected unauthorized_client"),
            }
        }

        #[test]
        fn unauthorized_client_null_description_becomes_none() {
            let payload = r#"
            {
                "error": "unauthorized_client",
                "error_description": null
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnauthorizedClient { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected unauthorized_client"),
            }
        }

        #[test]
        fn unauthorized_client_ignores_send_access_error_type_and_extra_fields() {
            let payload = r#"
            {
                "error": "unauthorized_client",
                "send_access_error_type": "should_be_ignored",
                "extra_field": true
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnauthorizedClient { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected unauthorized_client"),
            }
        }
    }

    mod send_access_token_unsupported_grant_type_error_tests {
        use serde_json::{from_str, json, to_value};

        use super::*;

        #[test]
        fn unsupported_grant_type_full_payload_with_description_parses() {
            let payload = json!({
                "error": "unsupported_grant_type",
                "error_description": "This grant type is not enabled."
            })
            .to_string();

            let parsed: SendAccessTokenApiErrorResponse = from_str(&payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnsupportedGrantType { error_description } => {
                    assert_eq!(
                        error_description.as_deref(),
                        Some("This grant type is not enabled.")
                    );
                }
                _ => panic!("expected unsupported_grant_type"),
            }
        }

        #[test]
        fn unsupported_grant_type_without_description_is_allowed() {
            let payload = r#"{ "error": "unsupported_grant_type" }"#;

            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnsupportedGrantType { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected unsupported_grant_type"),
            }
        }

        #[test]
        fn unsupported_grant_type_serializes_back() {
            let value = SendAccessTokenApiErrorResponse::UnsupportedGrantType {
                error_description: Some("Disabled by feature flag".into()),
            };
            let j = to_value(value).unwrap();
            assert_eq!(
                j,
                json!({
                    "error": "unsupported_grant_type",
                    "error_description": "Disabled by feature flag"
                })
            );
        }

        #[test]
        fn unsupported_grant_type_minimal_payload_is_allowed() {
            let payload = r#"{ "error": "unsupported_grant_type" }"#;
            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnsupportedGrantType { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected unsupported_grant_type"),
            }
        }

        #[test]
        fn unsupported_grant_type_null_description_becomes_none() {
            let payload = r#"
        {
          "error": "unsupported_grant_type",
          "error_description": null
        }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnsupportedGrantType { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected unsupported_grant_type"),
            }
        }

        #[test]
        fn unsupported_grant_type_ignores_send_access_error_type_and_extra_fields() {
            let payload = r#"
            {
                "error": "unsupported_grant_type",
                "send_access_error_type": "should_be_ignored",
                "extra_field": "noise"
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::UnsupportedGrantType { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected unsupported_grant_type"),
            }
        }
    }

    mod send_access_token_invalid_scope_error_tests {
        use serde_json::{from_str, json, to_value};

        use super::*;

        #[test]
        fn invalid_scope_full_payload_with_description_parses() {
            let payload = json!({
                "error": "invalid_scope",
                "error_description": "Requested scope is not allowed."
            })
            .to_string();

            let parsed: SendAccessTokenApiErrorResponse = from_str(&payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidScope { error_description } => {
                    assert_eq!(
                        error_description.as_deref(),
                        Some("Requested scope is not allowed.")
                    );
                }
                _ => panic!("expected invalid_scope"),
            }
        }

        #[test]
        fn invalid_scope_without_description_is_allowed() {
            let payload = r#"{ "error": "invalid_scope" }"#;

            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidScope { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_scope"),
            }
        }

        #[test]
        fn invalid_scope_serializes_back() {
            let value = SendAccessTokenApiErrorResponse::InvalidScope {
                error_description: None,
            };
            let j = to_value(value).unwrap();
            assert_eq!(j, json!({ "error": "invalid_scope" }));
        }

        #[test]
        fn invalid_scope_minimal_payload_is_allowed() {
            let payload = r#"{ "error": "invalid_scope" }"#;
            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidScope { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_scope"),
            }
        }

        #[test]
        fn invalid_scope_null_description_becomes_none() {
            let payload = r#"
        {
          "error": "invalid_scope",
          "error_description": null
        }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidScope { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_scope"),
            }
        }

        #[test]
        fn invalid_scope_ignores_send_access_error_type_and_extra_fields() {
            let payload = r#"
            {
                "error": "invalid_scope",
                "send_access_error_type": "should_be_ignored",
                "extra_field": [1,2,3]
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidScope { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_scope"),
            }
        }
    }

    mod send_access_token_invalid_target_error_tests {
        use serde_json::{from_str, json, to_value};

        use super::*;

        #[test]
        fn invalid_target_full_payload_with_description_parses() {
            let payload = json!({
                "error": "invalid_target",
                "error_description": "Unknown or disallowed resource indicator."
            })
            .to_string();

            let parsed: SendAccessTokenApiErrorResponse = from_str(&payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidTarget { error_description } => {
                    assert_eq!(
                        error_description.as_deref(),
                        Some("Unknown or disallowed resource indicator.")
                    );
                }
                _ => panic!("expected invalid_target"),
            }
        }

        #[test]
        fn invalid_target_without_description_is_allowed() {
            let payload = r#"{ "error": "invalid_target" }"#;

            let parsed: SendAccessTokenApiErrorResponse = serde_json::from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidTarget { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_target"),
            }
        }

        #[test]
        fn invalid_target_serializes_back() {
            let value = SendAccessTokenApiErrorResponse::InvalidTarget {
                error_description: Some("Bad resource parameter".into()),
            };
            let j = to_value(value).unwrap();
            assert_eq!(
                j,
                json!({
                    "error": "invalid_target",
                    "error_description": "Bad resource parameter"
                })
            );
        }

        #[test]
        fn invalid_target_minimal_payload_is_allowed() {
            let payload = r#"{ "error": "invalid_target" }"#;
            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidTarget { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_target"),
            }
        }

        #[test]
        fn invalid_target_null_description_becomes_none() {
            let payload = r#"
        {
          "error": "invalid_target",
          "error_description": null
        }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidTarget { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_target"),
            }
        }

        #[test]
        fn invalid_target_ignores_send_access_error_type_and_extra_fields() {
            let payload = r#"
            {
                "error": "invalid_target",
                "send_access_error_type": "should_be_ignored",
                "extra_field": {"k":"v"}
            }"#;

            let parsed: SendAccessTokenApiErrorResponse = from_str(payload).unwrap();
            match parsed {
                SendAccessTokenApiErrorResponse::InvalidTarget { error_description } => {
                    assert!(error_description.is_none());
                }
                _ => panic!("expected invalid_target"),
            }
        }
    }

    #[test]
    fn unknown_top_level_error_rejects() {
        let payload = r#"{ "error": "totally_new_error" }"#;
        let err = serde_json::from_str::<SendAccessTokenApiErrorResponse>(payload).unwrap_err();
        let _ = err;
    }
}
