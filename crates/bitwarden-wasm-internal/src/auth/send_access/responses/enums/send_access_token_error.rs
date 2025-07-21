use serde::Deserialize;

#[derive(Deserialize, PartialEq, Eq, Debug)]
pub enum SendAccessTokenError {
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "invalid_grant")]
    InvalidGrant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_send_access_token_error_invalid_request() {
        let error: String = "\"invalid_request\"".to_string();
        let result: SendAccessTokenError = serde_json::from_str(&error).unwrap();

        assert_eq!(result, SendAccessTokenError::InvalidRequest);
    }

    #[test]
    fn test_deserialize_send_access_token_error_invalid_grant() {
        let error: String = "\"invalid_grant\"".to_string();
        let result: SendAccessTokenError = serde_json::from_str(&error).unwrap();
        assert_eq!(result, SendAccessTokenError::InvalidGrant);
    }
}
