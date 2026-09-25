//! Parses the server's RFC 7807 validation problem error format.
//!
//! Endpoints that expose stable error codes answer a failed request with a validation problem on
//! `400`:
//!
//! ```json
//! {
//!   "type": "validation_error",
//!   "status": 400,
//!   "errors": { "code": [{ "type": "already_organization_member", "detail": "..." }] }
//! }
//! ```
//!
//! Older servers (and endpoints not yet migrated) answer with the legacy `ErrorResponseModel`
//! (`{ "message": "...", ... }`), which carries no code and is not a validation problem.

use std::collections::HashMap;

use bitwarden_core::ApiError;
use http::StatusCode;
use serde::Deserialize;

/// The subset of the server's RFC 7807 validation problem needed to extract error codes.
#[derive(Deserialize)]
pub(crate) struct ValidationProblem {
    errors: HashMap<String, Vec<ValidationErrorCode>>,
}

#[derive(Deserialize)]
struct ValidationErrorCode {
    #[serde(rename = "type")]
    code: String,
}

impl ValidationProblem {
    /// Parses the validation problem carried by an API error, or returns `None` if the error is not
    /// a `400` response with a validation problem body (e.g. a transport error, another status, or
    /// the legacy error format).
    pub(crate) fn from_api_error(error: &ApiError) -> Option<Self> {
        let ApiError::Response(content) = error else {
            return None;
        };
        if content.status != StatusCode::BAD_REQUEST {
            return None;
        }
        serde_json::from_str(&content.message).ok()
    }

    /// Returns the first error code in the problem, or `None` if it carries no errors.
    pub(crate) fn into_first_code(self) -> Option<String> {
        self.errors
            .into_values()
            .flatten()
            .next()
            .map(|error| error.code)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use bitwarden_api_api::ResponseContent;

    use super::*;

    pub(crate) fn response_error(status: u16, body: &str) -> ApiError {
        ApiError::Response(ResponseContent {
            status: status.try_into().expect("valid status code"),
            message: body.to_string(),
        })
    }

    pub(crate) fn validation_problem(property: &str, code: &str) -> String {
        format!(
            r#"{{"type":"validation_error","title":"One or more validation errors occurred.","status":400,"errors":{{"{property}":[{{"type":"{code}","detail":"Some detail."}}]}}}}"#
        )
    }

    fn first_code(status: u16, body: &str) -> Option<String> {
        ValidationProblem::from_api_error(&response_error(status, body))?.into_first_code()
    }

    #[test]
    fn parses_first_code() {
        let code = first_code(400, &validation_problem("code", "some_code"));
        assert_eq!(code.as_deref(), Some("some_code"));
    }

    #[test]
    fn parses_problem_without_errors() {
        let code = first_code(
            400,
            r#"{"type":"validation_error","status":400,"errors":{}}"#,
        );
        assert_eq!(code, None);
    }

    #[test]
    fn rejects_legacy_body() {
        let error = response_error(
            400,
            r#"{"message":"You're already a member of Acme.","validationErrors":null,"object":"error"}"#,
        );
        assert!(ValidationProblem::from_api_error(&error).is_none());
    }

    #[test]
    fn rejects_model_binding_problem() {
        // ASP.NET's default validation problem uses plain strings rather than error codes.
        let error = response_error(
            400,
            r#"{"type":"https://tools.ietf.org/html/rfc9110#section-15.5.1","status":400,"errors":{"Code":["The Code field is required."]}}"#,
        );
        assert!(ValidationProblem::from_api_error(&error).is_none());
    }

    #[test]
    fn rejects_other_statuses() {
        let error = response_error(500, &validation_problem("code", "some_code"));
        assert!(ValidationProblem::from_api_error(&error).is_none());
    }

    #[test]
    fn rejects_transport_errors() {
        let error = ApiError::from(std::io::Error::other("boom"));
        assert!(ValidationProblem::from_api_error(&error).is_none());
    }
}
