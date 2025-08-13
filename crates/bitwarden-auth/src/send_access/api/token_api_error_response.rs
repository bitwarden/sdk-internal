use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// Invalid request errors - typically due to missing parameters.
pub enum SendAccessTokenInvalidRequestError {
    #[serde(rename = "send_id_required", alias = "send_id is required.")]
    #[allow(missing_docs)]
    SendIdRequired,

    #[serde(
        rename = "password_hash_b64_required",
        alias = "password_hash_b64 is required."
    )]
    #[allow(missing_docs)]
    PasswordHashRequired,

    #[serde(rename = "email_required", alias = "email is required.")]
    #[allow(missing_docs)]
    EmailRequired,

    #[serde(
        rename = "email_and_otp_required_otp_sent",
        alias = "email and otp are required. An OTP has been sent to the email address provided."
    )]
    #[allow(missing_docs)]
    EmailAndOtpRequiredOtpSent,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// Invalid grant errors - typically due to invalid credentials.
pub enum SendAccessTokenInvalidGrantError {
    #[allow(missing_docs)]
    #[serde(rename = "send_id_invalid", alias = "send_id is invalid.")]
    InvalidSendId,

    #[allow(missing_docs)]
    #[serde(
        rename = "password_hash_b64_invalid",
        alias = "password_hash_b64 is invalid."
    )]
    InvalidPasswordHash,

    #[allow(missing_docs)]
    #[serde(rename = "email_invalid", alias = "email is invalid.")]
    InvalidEmail,

    #[allow(missing_docs)]
    #[serde(rename = "otp_invalid", alias = "otp is invalid.")]
    InvalidOtp,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(tag = "error", content = "error_description")]
// ^ "error" becomes the variant discriminator which matches against the rename annotations;
// "error_description" is the payload for that variant which can be optional.
/// Represents the possible, expected errors that can occur when requesting a send access token.
pub enum SendAccessTokenApiErrorResponse {
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

    mod send_access_token_invalid_request_error_tests {
        use super::*;
        use serde_json::{from_str, to_string, to_value, Value};

        #[test]
        fn invalid_request_variants_support_alias_and_emit_codes() {
            // (expected_variant, code_json, sentence_json)
            let cases: &[(SendAccessTokenInvalidRequestError, &str, &str)] = &[
            (
                SendAccessTokenInvalidRequestError::SendIdRequired,
                "\"send_id_required\"",
                "\"send_id is required.\"",
            ),
            (
                SendAccessTokenInvalidRequestError::PasswordHashRequired,
                "\"password_hash_b64_required\"",
                "\"password_hash_b64 is required.\"",
            ),
            (
                SendAccessTokenInvalidRequestError::EmailRequired,
                "\"email_required\"",
                "\"email is required.\"",
            ),
            (
                SendAccessTokenInvalidRequestError::EmailAndOtpRequiredOtpSent,
                "\"email_and_otp_required_otp_sent\"",
                "\"email and otp are required. An OTP has been sent to the email address provided.\"",
            ),
        ];

            for (expected_variant, code_json, sentence_json) in cases {
                // 1) Deserializing the server's sentence alias -> enum
                let error_from_sentence: SendAccessTokenInvalidRequestError =
                    from_str(sentence_json).unwrap();
                assert_eq!(
                    &error_from_sentence, expected_variant,
                    "sentence alias should map to the expected variant"
                );

                // 2) Deserializing the canonical code -> enum
                let error_from_code: SendAccessTokenInvalidRequestError =
                    from_str(code_json).unwrap();
                assert_eq!(
                    &error_from_code, expected_variant,
                    "code should map to the expected variant"
                );

                // 3a) Serializing enum -> JSON string containing the canonical code (includes quotes)
                let json_from_variant = to_string(expected_variant).unwrap();
                assert_eq!(
                    json_from_variant, *code_json,
                    "serialization should emit the canonical code string"
                );

                // 3b) (Optional) Type-safe check: to_value() → Value::String, then compare the code;
                // this avoids formatting/quoting concerns from to_string().
                let value_from_variant = to_value(expected_variant).unwrap();
                assert_eq!(
                    value_from_variant,
                    Value::String(code_json.trim_matches('"').to_string()),
                    "serialization as Value should be the canonical code"
                );

                // 4) Round-trip: sentence alias -> enum -> canonical code
                let round_tripped_code = to_string(&error_from_sentence).unwrap();
                assert_eq!(
                    round_tripped_code, *code_json,
                    "alias should round-trip to the canonical code"
                );
            }
        }

        #[test]
        fn invalid_request_unknown_sentence_fails() {
            // No #[serde(other)] variant defined, so unknown strings should fail to parse.
            let unknown_sentence_json = "\"this is not a known invalid_request sentence\"";
            let err =
                from_str::<SendAccessTokenInvalidRequestError>(unknown_sentence_json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown variant") || msg.contains("expected"),
                "unexpected error: {msg}"
            );
        }

        #[test]
        fn invalid_request_unknown_code_fails() {
            let unknown_code_json = "\"not_a_real_invalid_request_code\"";
            let err =
                from_str::<SendAccessTokenInvalidRequestError>(unknown_code_json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown variant") || msg.contains("expected"),
                "unexpected error: {msg}"
            );
        }
    }

    mod send_access_token_invalid_grant_error_tests {
        use super::*;
        use serde_json::{from_str, to_string, to_value, Value};

        #[test]
        fn invalid_grant_variants_support_alias_and_emit_codes() {
            // (variant, code_json, sentence_json)
            let cases: &[(SendAccessTokenInvalidGrantError, &str, &str)] = &[
                (
                    SendAccessTokenInvalidGrantError::InvalidSendId,
                    "\"send_id_invalid\"",
                    "\"send_id is invalid.\"",
                ),
                (
                    SendAccessTokenInvalidGrantError::InvalidPasswordHash,
                    "\"password_hash_b64_invalid\"",
                    "\"password_hash_b64 is invalid.\"",
                ),
                (
                    SendAccessTokenInvalidGrantError::InvalidEmail,
                    "\"email_invalid\"",
                    "\"email is invalid.\"",
                ),
                (
                    SendAccessTokenInvalidGrantError::InvalidOtp,
                    "\"otp_invalid\"",
                    "\"otp is invalid.\"",
                ),
            ];

            for (expected_variant, code_json, sentence_json) in cases {
                // 1) Deserializing the server's sentence alias -> enum
                let error_from_sentence: SendAccessTokenInvalidGrantError =
                    from_str(sentence_json).unwrap();
                assert_eq!(
                    &error_from_sentence, expected_variant,
                    "sentence alias should map to the expected variant"
                );

                // 2) Deserializing the canonical code -> enum
                let error_from_code: SendAccessTokenInvalidGrantError =
                    from_str(code_json).unwrap();
                assert_eq!(
                    &error_from_code, expected_variant,
                    "code should map to the expected variant"
                );

                // 3a) Serializing enum -> JSON string containing the canonical code (includes quotes)
                let json_from_variant = to_string(expected_variant).unwrap();
                assert_eq!(
                    json_from_variant, *code_json,
                    "serialization should emit the canonical code string"
                );

                // 3b) (Optional) Type-safe check: to_value() → Value::String, then compare the code;
                // this avoids formatting/quoting concerns from to_string().
                let value_from_variant = to_value(expected_variant).unwrap();
                assert_eq!(
                    value_from_variant,
                    Value::String(code_json.trim_matches('"').to_string()),
                    "serialization as Value should be the canonical code"
                );

                // 4) Round-trip: sentence alias -> enum -> canonical code
                let round_tripped_code = to_string(&error_from_sentence).unwrap();
                assert_eq!(
                    round_tripped_code, *code_json,
                    "alias should round-trip to the canonical code"
                );
            }
        }

        #[test]
        fn invalid_grant_unknown_sentence_fails() {
            // No #[serde(other)] variant defined, so unknown strings should fail to parse.
            let unknown_sentence_json = "\"this is not a known invalid_grant sentence\"";
            let err =
                from_str::<SendAccessTokenInvalidGrantError>(unknown_sentence_json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown variant") || msg.contains("expected"),
                "unexpected error: {msg}"
            );
        }

        #[test]
        fn invalid_grant_unknown_code_fails() {
            let unknown_code_json = "\"not_a_real_invalid_grant_code\"";
            let err = from_str::<SendAccessTokenInvalidGrantError>(unknown_code_json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown variant") || msg.contains("expected"),
                "unexpected error: {msg}"
            );
        }
    }

    mod send_access_token_error_tests {
        use super::*;
        use serde_json::{from_str, to_string};

        #[test]
        fn deserializes_invalid_request_without_details() {
            let json = r#"{ "error": "invalid_request" }"#;
            let result: SendAccessTokenApiErrorResponse = from_str(json).unwrap();
            assert_eq!(
                result,
                SendAccessTokenApiErrorResponse::InvalidRequest(None)
            );
        }

        #[test]
        fn deserializes_invalid_grant_without_details() {
            let json = r#"{ "error": "invalid_grant" }"#;
            let result: SendAccessTokenApiErrorResponse = from_str(json).unwrap();
            assert_eq!(result, SendAccessTokenApiErrorResponse::InvalidGrant(None));
        }

        // --- With details: ALIAS (sentence) -> enum

        #[test]
        fn deserializes_invalid_request_with_sentence_detail() {
            let json =
                r#"{ "error": "invalid_request", "error_description": "send_id is required." }"#;
            let result: SendAccessTokenApiErrorResponse = from_str(json).unwrap();
            assert_eq!(
                result,
                SendAccessTokenApiErrorResponse::InvalidRequest(Some(
                    SendAccessTokenInvalidRequestError::SendIdRequired
                ))
            );
        }

        #[test]
        fn deserializes_invalid_grant_with_sentence_detail() {
            let json = r#"{ "error": "invalid_grant", "error_description": "password_hash_b64 is invalid." }"#;
            let result: SendAccessTokenApiErrorResponse = from_str(json).unwrap();
            assert_eq!(
                result,
                SendAccessTokenApiErrorResponse::InvalidGrant(Some(
                    SendAccessTokenInvalidGrantError::InvalidPasswordHash
                ))
            );
        }

        // --- With details: CODE -> enum

        #[test]
        fn deserializes_invalid_request_with_code_detail() {
            let json = r#"{ "error": "invalid_request", "error_description": "send_id_required" }"#;
            let result: SendAccessTokenApiErrorResponse = from_str(json).unwrap();
            assert_eq!(
                result,
                SendAccessTokenApiErrorResponse::InvalidRequest(Some(
                    SendAccessTokenInvalidRequestError::SendIdRequired
                ))
            );
        }

        #[test]
        fn deserializes_invalid_request_with_code_detail_email_and_otp_required() {
            // Note: matches your Rust rename "email_and_otp_required_otp_sent"
            let json = r#"{ "error": "invalid_request", "error_description": "email_and_otp_required_otp_sent" }"#;
            let result: SendAccessTokenApiErrorResponse = from_str(json).unwrap();
            assert_eq!(
                result,
                SendAccessTokenApiErrorResponse::InvalidRequest(Some(
                    SendAccessTokenInvalidRequestError::EmailAndOtpRequiredOtpSent
                ))
            );
        }

        #[test]
        fn deserializes_invalid_grant_with_code_detail() {
            let json =
                r#"{ "error": "invalid_grant", "error_description": "password_hash_b64_invalid" }"#;
            let result: SendAccessTokenApiErrorResponse = from_str(json).unwrap();
            assert_eq!(
                result,
                SendAccessTokenApiErrorResponse::InvalidGrant(Some(
                    SendAccessTokenInvalidGrantError::InvalidPasswordHash
                ))
            );
        }

        // --- enum -> JSON: should always emit the CODE (not the sentence)

        #[test]
        fn serializes_invalid_request_with_detail_emits_code() {
            let e = SendAccessTokenApiErrorResponse::InvalidRequest(Some(
                SendAccessTokenInvalidRequestError::EmailAndOtpRequiredOtpSent,
            ));
            let json = to_string(&e).unwrap();
            assert_eq!(
                json,
                r#"{"error":"invalid_request","error_description":"email_and_otp_required_otp_sent"}"#
            );
        }

        #[test]
        fn serializes_invalid_grant_with_detail_emits_code() {
            let e = SendAccessTokenApiErrorResponse::InvalidGrant(Some(
                SendAccessTokenInvalidGrantError::InvalidPasswordHash,
            ));
            let json = to_string(&e).unwrap();
            assert_eq!(
                json,
                r#"{"error":"invalid_grant","error_description":"password_hash_b64_invalid"}"#
            );
        }

        // --- Round-trip: sentence -> enum -> code

        #[test]
        fn round_trips_sentence_detail_to_code_for_invalid_request() {
            let in_json = r#"{ "error": "invalid_request", "error_description": "email and otp are required. An OTP has been sent to the email address provided." }"#;
            let parsed: SendAccessTokenApiErrorResponse = from_str(in_json).unwrap();
            let out_json = to_string(&parsed).unwrap();
            assert_eq!(
                out_json,
                r#"{"error":"invalid_request","error_description":"email_and_otp_required_otp_sent"}"#
            );
        }

        #[test]
        fn round_trips_sentence_detail_to_code_for_invalid_grant() {
            let in_json = r#"{ "error": "invalid_grant", "error_description": "otp is invalid." }"#;
            let parsed: SendAccessTokenApiErrorResponse = from_str(in_json).unwrap();
            let out_json = to_string(&parsed).unwrap();
            assert_eq!(
                out_json,
                r#"{"error":"invalid_grant","error_description":"otp_invalid"}"#
            );
        }

        // --- Negative: unknown detail should fail to parse (no #[serde(other)] present)

        #[test]
        fn deserializing_unknown_detail_fails_for_invalid_request() {
            let json = r#"{ "error": "invalid_request", "error_description": "totally unknown" }"#;
            let err = from_str::<SendAccessTokenApiErrorResponse>(json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown variant") || msg.contains("expected"),
                "unexpected error: {msg}"
            );
        }

        #[test]
        fn deserializing_unknown_detail_fails_for_invalid_grant() {
            let json = r#"{ "error": "invalid_grant", "error_description": "not_a_real_code" }"#;
            let err = from_str::<SendAccessTokenApiErrorResponse>(json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown variant") || msg.contains("expected"),
                "unexpected error: {msg}"
            );
        }
    }
}
