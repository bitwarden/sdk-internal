use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// Invalid request errors - typically due to missing parameters.
pub enum SendAccessTokenInvalidRequestError {
    #[serde(rename = "send_id is required.")]
    #[allow(missing_docs)]
    SendIdRequired,

    #[serde(rename = "password_hash is required.")]
    #[allow(missing_docs)]
    PasswordHashRequired,

    #[serde(rename = "Email is required.")]
    #[allow(missing_docs)]
    EmailRequired,

    #[serde(
        rename = "Email and OTP are required. An OTP has been sent to the email address provided."
    )]
    #[allow(missing_docs)]
    EmailAndOtpRequiredOtpSent,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// Invalid grant errors - typically due to invalid credentials.
pub enum SendAccessTokenInvalidGrantError {
    #[allow(missing_docs)]
    #[serde(rename = "Password_hash invalid.")]
    InvalidPasswordHash,

    #[allow(missing_docs)]
    #[serde(rename = "Email invalid.")]
    InvalidEmail,

    #[allow(missing_docs)]
    #[serde(rename = "OTP invalid.")]
    InvalidOtp,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(tag = "error", content = "error_description")]
// ^ "error" becomes the variant discriminator which matches against the rename annotations;
// "error_description" is the payload for that variant which can be optional.
/// Represents the possible errors that can occur when requesting a send access token.
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

        #[test]
        fn test_deserialize_send_token_error_desc_send_id_required() {
            let error_desc: String = "\"send_id is required.\"".to_string();
            let result: SendAccessTokenInvalidRequestError =
                serde_json::from_str(&error_desc).unwrap();

            assert_eq!(result, SendAccessTokenInvalidRequestError::SendIdRequired);
        }

        #[test]
        fn test_deserialize_send_token_error_desc_password_hash_required() {
            let error_desc: String = "\"Password_hash is required.\"".to_string();
            let result: SendAccessTokenInvalidRequestError =
                serde_json::from_str(&error_desc).unwrap();
            assert_eq!(
                result,
                SendAccessTokenInvalidRequestError::PasswordHashRequired
            );
        }

        #[test]
        fn test_deserialize_send_token_error_desc_email_required() {
            let error_desc: String = "\"Email is required.\"".to_string();
            let result: SendAccessTokenInvalidRequestError =
                serde_json::from_str(&error_desc).unwrap();
            assert_eq!(result, SendAccessTokenInvalidRequestError::EmailRequired);
        }

        #[test]
        fn test_deserialize_send_token_error_desc_email_and_otp_required() {
            let error_desc: String =
            "\"Email and OTP are required. An OTP has been sent to the email address provided.\""
                .to_string();
            let result: SendAccessTokenInvalidRequestError =
                serde_json::from_str(&error_desc).unwrap();
            assert_eq!(
                result,
                SendAccessTokenInvalidRequestError::EmailAndOtpRequiredOtpSent
            );
        }
    }

    mod send_access_token_invalid_grant_error_tests {
        use super::*;

        #[test]
        fn test_deserialize_send_token_error_desc_invalid_password_hash() {
            let error_desc: String = "\"Password_hash invalid.\"".to_string();
            let result: SendAccessTokenInvalidGrantError =
                serde_json::from_str(&error_desc).unwrap();
            assert_eq!(
                result,
                SendAccessTokenInvalidGrantError::InvalidPasswordHash
            );
        }

        #[test]
        fn test_deserialize_send_token_error_desc_invalid_email() {
            let error_desc: String = "\"Email invalid.\"".to_string();
            let result: SendAccessTokenInvalidGrantError =
                serde_json::from_str(&error_desc).unwrap();
            assert_eq!(result, SendAccessTokenInvalidGrantError::InvalidEmail);
        }

        #[test]
        fn test_deserialize_send_token_error_desc_invalid_otp() {
            let error_desc: String = "\"OTP invalid.\"".to_string();
            let result: SendAccessTokenInvalidGrantError =
                serde_json::from_str(&error_desc).unwrap();
            assert_eq!(result, SendAccessTokenInvalidGrantError::InvalidOtp);
        }
    }

    mod send_access_token_error_tests {
        use super::*;

        #[test]
        fn test_deserialize_send_access_token_error_invalid_request() {
            let obj = r#"{ "error": "invalid_request" }"#;
            let result: SendAccessTokenApiErrorResponse = serde_json::from_str(obj).unwrap();
            assert_eq!(
                result,
                SendAccessTokenApiErrorResponse::InvalidRequest(None)
            );
        }

        #[test]
        fn test_deserialize_send_access_token_error_invalid_grant() {
            let obj = r#"{ "error": "invalid_grant" }"#;
            let result: SendAccessTokenApiErrorResponse = serde_json::from_str(obj).unwrap();
            assert_eq!(result, SendAccessTokenApiErrorResponse::InvalidGrant(None));
        }

        #[test]
        fn test_deserialize_send_access_token_error_invalid_request_with_details() {
            let obj =
                r#"{ "error": "invalid_request", "error_description": "send_id is required." }"#;
            let result: SendAccessTokenApiErrorResponse = serde_json::from_str(obj).unwrap();
            assert_eq!(
                result,
                SendAccessTokenApiErrorResponse::InvalidRequest(Some(
                    SendAccessTokenInvalidRequestError::SendIdRequired
                ))
            );
        }

        #[test]
        fn test_deserialize_send_access_token_error_invalid_grant_with_details() {
            let obj =
                r#"{ "error": "invalid_grant", "error_description": "Password_hash invalid." }"#;
            let result: SendAccessTokenApiErrorResponse = serde_json::from_str(obj).unwrap();
            assert_eq!(
                result,
                SendAccessTokenApiErrorResponse::InvalidGrant(Some(
                    SendAccessTokenInvalidGrantError::InvalidPasswordHash
                ))
            );
        }
    }
}
