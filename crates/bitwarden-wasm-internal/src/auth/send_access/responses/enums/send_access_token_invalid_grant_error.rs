use serde::Deserialize;

#[derive(Deserialize, PartialEq, Eq, Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_send_token_error_desc_invalid_password_hash() {
        let error_desc: String = "\"Password_hash invalid.\"".to_string();
        let result: SendAccessTokenInvalidGrantError = serde_json::from_str(&error_desc).unwrap();
        assert_eq!(
            result,
            SendAccessTokenInvalidGrantError::InvalidPasswordHash
        );
    }

    #[test]
    fn test_deserialize_send_token_error_desc_invalid_email() {
        let error_desc: String = "\"Email invalid.\"".to_string();
        let result: SendAccessTokenInvalidGrantError = serde_json::from_str(&error_desc).unwrap();
        assert_eq!(result, SendAccessTokenInvalidGrantError::InvalidEmail);
    }

    #[test]
    fn test_deserialize_send_token_error_desc_invalid_otp() {
        let error_desc: String = "\"OTP invalid.\"".to_string();
        let result: SendAccessTokenInvalidGrantError = serde_json::from_str(&error_desc).unwrap();
        assert_eq!(result, SendAccessTokenInvalidGrantError::InvalidOtp);
    }
}
