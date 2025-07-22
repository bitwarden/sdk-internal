use serde::Deserialize;

#[derive(Deserialize, PartialEq, Eq, Debug)]
/// Invalid request errors - typically due to missing parameters.
pub enum SendAccessTokenInvalidRequestError {
    #[serde(rename = "send_id is required.")]
    #[allow(missing_docs)]
    SendIdRequired,

    #[serde(rename = "Password_hash is required.")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_send_token_error_desc_send_id_required() {
        let error_desc: String = "\"send_id is required.\"".to_string();
        let result: SendAccessTokenInvalidRequestError = serde_json::from_str(&error_desc).unwrap();

        assert_eq!(result, SendAccessTokenInvalidRequestError::SendIdRequired);
    }

    #[test]
    fn test_deserialize_send_token_error_desc_password_hash_required() {
        let error_desc: String = "\"Password_hash is required.\"".to_string();
        let result: SendAccessTokenInvalidRequestError = serde_json::from_str(&error_desc).unwrap();
        assert_eq!(
            result,
            SendAccessTokenInvalidRequestError::PasswordHashRequired
        );
    }

    #[test]
    fn test_deserialize_send_token_error_desc_email_required() {
        let error_desc: String = "\"Email is required.\"".to_string();
        let result: SendAccessTokenInvalidRequestError = serde_json::from_str(&error_desc).unwrap();
        assert_eq!(result, SendAccessTokenInvalidRequestError::EmailRequired);
    }

    #[test]
    fn test_deserialize_send_token_error_desc_email_and_otp_required() {
        let error_desc: String =
            "\"Email and OTP are required. An OTP has been sent to the email address provided.\""
                .to_string();
        let result: SendAccessTokenInvalidRequestError = serde_json::from_str(&error_desc).unwrap();
        assert_eq!(
            result,
            SendAccessTokenInvalidRequestError::EmailAndOtpRequiredOtpSent
        );
    }
}
