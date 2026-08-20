//! Reading the codes out of a PAM problem response.
//!
//! The server answers a refused PAM request with an RFC 7807 problem whose stable, machine-readable
//! code sits at `errors.<property>[].type`. That code is the contract - never localized, never
//! reworded - so it, and not the human-readable `detail` beside it, is what this SDK switches on to
//! pick a typed error variant.
//!
//! Lives in this crate because PAM is the first surface to speak it. Nothing here is
//! PAM-specific; when a second crate needs it, lift it into `bitwarden-core` unchanged.

use bitwarden_core::ApiError;
use serde::Deserialize;

/// The slice of an RFC 7807 body worth reading. Everything else - `type`, `title`, `status`,
/// `detail` - is either display copy or already known from the response itself.
#[derive(Deserialize)]
struct ProblemBody {
    errors: Option<std::collections::BTreeMap<String, Vec<ProblemCode>>>,
}

#[derive(Deserialize)]
struct ProblemCode {
    #[serde(rename = "type")]
    code: String,
}

/// Every code the server put in the body, in a stable order.
///
/// Empty for a transport failure, a non-problem body, or a problem carrying no codes - all of which
/// leave the caller with the untyped [`ApiError`] it started with. Model-state rejections are one
/// such case: they answer with the server's older `ErrorResponseModel` body and carry no code,
/// because a request that never bound cleanly leaves nothing for a client to act on differently.
///
/// A refused PAM request carries exactly one code; the signature stays plural so a body naming
/// several fields at once does not need this to change.
pub(crate) fn codes(error: &ApiError) -> Vec<String> {
    let ApiError::Response(content) = error else {
        return Vec::new();
    };

    let Ok(body) = serde_json::from_str::<ProblemBody>(&content.message) else {
        return Vec::new();
    };

    body.errors
        .unwrap_or_default()
        .into_values()
        .flatten()
        .map(|entry| entry.code)
        .collect()
}

/// Applies `classify` to each code the server returned, returning the first match.
///
/// An unrecognized code yields `None`, so a server that grows a code no client release has seen
/// degrades to the generic transport error rather than to the wrong typed variant.
pub(crate) fn classify<T>(error: &ApiError, classify: impl Fn(&str) -> Option<T>) -> Option<T> {
    codes(error).iter().find_map(|code| classify(code))
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::ResponseContent;
    use reqwest::StatusCode;

    use super::*;

    fn response(status: StatusCode, body: &str) -> ApiError {
        ApiError::Response(ResponseContent {
            status,
            message: body.to_string(),
        })
    }

    #[test]
    fn codes_reads_the_code_out_of_a_problem_body() {
        let error = response(
            StatusCode::BAD_REQUEST,
            r#"{"type":"validation_error","status":400,"errors":{"reason":[{"type":"reason_required","detail":"A reason is required."}]}}"#,
        );

        assert_eq!(codes(&error), vec!["reason_required"]);
    }

    #[test]
    fn codes_reads_a_conflict_the_same_way_as_a_validation_failure() {
        // The status differs so a caller that reads no further still learns something, but the body
        // is identical - one parser covers both.
        let error = response(
            StatusCode::CONFLICT,
            r#"{"type":"conflict_error","status":409,"errors":{"code":[{"type":"access_already_active","detail":"You already have active access to this item."}]}}"#,
        );

        assert_eq!(codes(&error), vec!["access_already_active"]);
    }

    #[test]
    fn codes_reads_every_code_in_a_body_naming_several_properties() {
        // The server sends one code per refusal today. This pins the ordering anyway, so a body
        // that grows a second entry classifies deterministically rather than by map iteration.
        let error = response(
            StatusCode::BAD_REQUEST,
            r#"{"type":"validation_error","errors":{"reason":[{"type":"reason_required","detail":"x"}],"durationSeconds":[{"type":"duration_exceeds_max","detail":"y"}]}}"#,
        );

        // Ordered by property name, so a caller matching several codes gets the same answer twice.
        assert_eq!(
            codes(&error),
            vec!["duration_exceeds_max", "reason_required"]
        );
    }

    #[test]
    fn codes_is_empty_for_a_body_that_is_not_a_problem() {
        // The shape a model-state rejection still answers with: no codes, so the caller keeps the
        // generic `Api` error rather than being handed a wrong typed variant.
        let error = response(
            StatusCode::BAD_REQUEST,
            r#"{"object":"error","message":"Something went wrong."}"#,
        );

        assert!(codes(&error).is_empty());
    }

    #[test]
    fn codes_is_empty_for_a_transport_failure() {
        let error = ApiError::Io(std::io::Error::other("connection reset"));

        assert!(codes(&error).is_empty());
    }

    #[test]
    fn classify_ignores_a_code_this_version_does_not_know() {
        let error = response(
            StatusCode::BAD_REQUEST,
            r#"{"errors":{"code":[{"type":"invented_next_year"}]}}"#,
        );

        assert_eq!(
            classify(&error, |code| (code == "reason_required").then_some(())),
            None
        );
    }
}
