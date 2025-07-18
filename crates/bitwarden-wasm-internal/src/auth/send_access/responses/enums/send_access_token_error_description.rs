use serde::Deserialize;

// TODO: if we convert to numeric enum on server for these responses,
// we can use serde_repr to map them directly to a numeric enum in Rust.
// We could also consider getting the type for free with generated bindings from OpenAPI.

#[derive(Deserialize, PartialEq, Eq, Debug)]
pub enum SendAccessTokenErrorDescription {
    #[serde(rename = "send_id is required.")]
    SendIdRequired,
    #[serde(rename = "Password_hash is required.")]
    PasswordHashRequired,
    EmailRequired,
    EmailAndOtpRequired,
    #[serde(rename = "Password_hash invalid.")]
    InvalidPasswordHash,
    #[serde(rename = "Invalid OTP.")]
    InvalidOtp,
}

// export type SendTokenApiError =
//   | "invalid-request"
//   | "send-id-required"
//   | "password-hash-required"
//   | "email-and-otp-required"
//   | "invalid-grant"
//   | "invalid-password-hash"
//   | "invalid-otp"
//   | "json-parse-error"
//   | "unknown-error";

// const INVALID_REQUEST_ERROR_MAPPING: Record<string, SendTokenApiError> = {
//   "send_id is required.": "send-id-required",
//   "Password hash is required.": "password-hash-required",
//   "": "invalid-request", // This is a catch-all for any null/undefined invalid request error descriptions
// };

// const INVALID_GRANT_ERROR_MAPPING: Record<string, SendTokenApiError> = {
//   "Password hash invalid.": "invalid-password-hash",
//   "Invalid OTP.": "invalid-otp",
//   "": "invalid-grant", // This is a catch-all for any null/undefined invalid grant error descriptions
// };

// Add unit test to ensure the enum can be deserialized correctly
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_send_token_api_error() {
        let error_desc: String = "\"send_id is required.\"".to_string();
        let result: SendAccessTokenErrorDescription = serde_json::from_str(&error_desc).unwrap();

        assert_eq!(result, SendAccessTokenErrorDescription::SendIdRequired);
    }
}
