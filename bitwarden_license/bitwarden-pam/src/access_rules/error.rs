use bitwarden_api_api::models::ErrorResponseModel;
use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::validate::AccessRuleValidationError;

/// Errors returned from [`super::AccessRulesClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AccessRuleError {
    /// The server rejected the request as malformed (HTTP 400 Bad Request).
    ///
    /// The display output is the server's own message verbatim (e.g. "A rule with that name
    /// already exists.") so clients can surface it to the user directly.
    #[error("{message}")]
    BadRequest {
        /// Human-readable reason the server rejected the request, extracted from the response
        /// body when possible.
        message: String,
    },
    /// The access rule could not be found. Returned for a missing rule, a rule belonging to a
    /// different organization, or when the server-side PAM feature is disabled.
    #[error("Access rule not found")]
    NotFound,
    /// The request failed local validation before being sent to the server.
    #[error(transparent)]
    Validation(#[from] AccessRuleValidationError),
    /// The `conditions` field of a server response could not be interpreted.
    #[error("Invalid conditions: {0}")]
    InvalidConditions(String),
    /// The server response was missing a field required to build the requested type.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A date field in the server response could not be parsed.
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    /// A network or (de)serialization error occurred while calling the server.
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// Maps an error from the generated access rules API client into an [`AccessRuleError`].
///
/// - `400 Bad Request` response bodies are parsed as the server's [`ErrorResponseModel`] to extract
///   a human-readable message, falling back to the raw response body when the body isn't in that
///   shape.
/// - `404 Not Found` maps to [`AccessRuleError::NotFound`].
/// - Everything else is wrapped into [`AccessRuleError::Api`].
pub(crate) fn map_api_error(error: bitwarden_api_api::apis::Error) -> AccessRuleError {
    if let bitwarden_api_api::apis::Error::Response(ref content) = error {
        match content.status {
            reqwest::StatusCode::BAD_REQUEST => {
                let message = serde_json::from_str::<ErrorResponseModel>(&content.message)
                    .ok()
                    .and_then(|body| body.message)
                    .unwrap_or_else(|| content.message.clone());
                return AccessRuleError::BadRequest { message };
            }
            reqwest::StatusCode::NOT_FOUND => return AccessRuleError::NotFound,
            _ => {}
        }
    }

    AccessRuleError::Api(error.into())
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ResponseContent;

    use super::*;

    fn response_error(
        status: reqwest::StatusCode,
        message: &str,
    ) -> bitwarden_api_api::apis::Error {
        bitwarden_api_api::apis::Error::Response(ResponseContent {
            status,
            message: message.to_string(),
        })
    }

    #[test]
    fn bad_request_with_server_error_body_extracts_message() {
        let body = serde_json::json!({ "message": "Name is required" }).to_string();
        let error = response_error(reqwest::StatusCode::BAD_REQUEST, &body);

        let mapped = map_api_error(error);

        assert!(matches!(
            mapped,
            AccessRuleError::BadRequest { message } if message == "Name is required"
        ));
    }

    #[test]
    fn bad_request_with_unparsable_body_falls_back_to_raw_body() {
        let error = response_error(reqwest::StatusCode::BAD_REQUEST, "not json");

        let mapped = map_api_error(error);

        assert!(matches!(
            mapped,
            AccessRuleError::BadRequest { message } if message == "not json"
        ));
    }

    #[test]
    fn not_found_maps_to_not_found_variant() {
        let error = response_error(reqwest::StatusCode::NOT_FOUND, "");

        let mapped = map_api_error(error);

        assert!(matches!(mapped, AccessRuleError::NotFound));
    }

    #[test]
    fn other_status_maps_to_api_error() {
        let error = response_error(reqwest::StatusCode::INTERNAL_SERVER_ERROR, "boom");

        let mapped = map_api_error(error);

        assert!(matches!(mapped, AccessRuleError::Api(_)));
    }
}
