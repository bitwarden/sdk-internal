//! Maps server error responses from the invite link acceptance endpoints onto typed
//! [`InviteLinkError`] variants.
//!
//! Servers that expose stable error codes answer a failed acceptance or confirmation with an
//! RFC 7807 validation problem on `400`:
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
//! (`{ "message": "...", ... }`), which carries no code. Those responses are left as
//! [`InviteLinkError::Api`] so existing clients that inspect the raw response keep working. A `404`
//! always maps to [`InviteLinkError::LinkNotFound`], regardless of body shape.

use std::collections::HashMap;

use bitwarden_core::ApiError;
use serde::Deserialize;

use crate::InviteLinkError;

/// The subset of the server's RFC 7807 validation problem needed to extract error codes.
#[derive(Deserialize)]
struct ValidationProblem {
    errors: HashMap<String, Vec<ValidationErrorCode>>,
}

#[derive(Deserialize)]
struct ValidationErrorCode {
    #[serde(rename = "type")]
    code: String,
}

/// Maps an error from an invite link acceptance endpoint (fetching the invite, accepting, or
/// confirming) onto an [`InviteLinkError`].
///
/// Only use this for those endpoints: a `404` is interpreted as the invite link not existing.
pub(crate) fn map_accept_error(error: ApiError) -> InviteLinkError {
    let ApiError::Response(content) = &error else {
        return InviteLinkError::Api(error);
    };

    match content.status.as_u16() {
        404 => InviteLinkError::LinkNotFound,
        400 => match first_validation_code(&content.message) {
            Some(code) => from_code(code),
            None => InviteLinkError::Api(error),
        },
        _ => InviteLinkError::Api(error),
    }
}

/// Returns the first error code from a validation problem body, or `None` if the body is not a
/// validation problem (e.g. the legacy error format).
fn first_validation_code(body: &str) -> Option<String> {
    let problem: ValidationProblem = serde_json::from_str(body).ok()?;
    problem
        .errors
        .into_values()
        .flatten()
        .next()
        .map(|error| error.code)
}

fn from_code(code: String) -> InviteLinkError {
    match code.as_str() {
        "invite_link_not_available" => InviteLinkError::InviteLinkNotAvailable,
        "invite_link_confirmation_not_supported" => {
            InviteLinkError::InviteLinkConfirmationNotSupported
        }
        "email_not_verified" => InviteLinkError::EmailNotVerified,
        "email_domain_not_allowed" => InviteLinkError::EmailDomainNotAllowed,
        "provider_users_cannot_join" => InviteLinkError::ProviderUsersCannotJoin,
        "organization_access_revoked" => InviteLinkError::OrganizationAccessRevoked,
        "already_organization_member" => InviteLinkError::AlreadyOrganizationMember,
        "organization_has_no_available_seats" => InviteLinkError::OrganizationHasNoAvailableSeats,
        "seat_add_failed" => InviteLinkError::SeatAddFailed,
        "reset_password_key_required" => InviteLinkError::ResetPasswordKeyRequired,
        "member_of_another_organization" => InviteLinkError::MemberOfAnotherOrganization,
        "single_organization_policy" => InviteLinkError::SingleOrganizationPolicy,
        "two_factor_required_for_membership" => InviteLinkError::TwoFactorRequiredForMembership,
        "only_one_free_organization_admin_allowed" => {
            InviteLinkError::OnlyOneFreeOrganizationAdminAllowed
        }
        _ => InviteLinkError::Unknown(code),
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

    fn validation_problem(property: &str, code: &str) -> String {
        format!(
            r#"{{"type":"validation_error","title":"One or more validation errors occurred.","status":400,"errors":{{"{property}":[{{"type":"{code}","detail":"Some detail."}}]}}}}"#
        )
    }

    fn map(status: u16, body: &str) -> InviteLinkError {
        map_accept_error(response_error(status, body))
    }

    #[test]
    fn maps_every_known_code() {
        let cases = [
            ("code", "invite_link_not_available"),
            ("code", "invite_link_confirmation_not_supported"),
            ("organizationId", "email_not_verified"),
            ("code", "email_domain_not_allowed"),
            ("code", "provider_users_cannot_join"),
            ("code", "organization_access_revoked"),
            ("code", "already_organization_member"),
            ("code", "organization_has_no_available_seats"),
            ("code", "seat_add_failed"),
            ("resetPasswordKey", "reset_password_key_required"),
            ("organizationId", "member_of_another_organization"),
            ("organizationId", "single_organization_policy"),
            ("organizationId", "two_factor_required_for_membership"),
            ("organizationId", "only_one_free_organization_admin_allowed"),
        ];

        for (property, code) in cases {
            let error = map(400, &validation_problem(property, code));
            assert!(
                !matches!(error, InviteLinkError::Unknown(_) | InviteLinkError::Api(_)),
                "`{code}` should map to a typed variant, got {error:?}"
            );
        }
    }

    #[test]
    fn maps_already_organization_member() {
        let error = map(
            400,
            &validation_problem("code", "already_organization_member"),
        );
        assert!(matches!(error, InviteLinkError::AlreadyOrganizationMember));
    }

    #[test]
    fn maps_email_not_verified() {
        let error = map(
            400,
            &validation_problem("organizationId", "email_not_verified"),
        );
        assert!(matches!(error, InviteLinkError::EmailNotVerified));
    }

    #[test]
    fn maps_unmapped_code_to_unknown() {
        let error = map(400, &validation_problem("code", "some_future_code"));
        assert!(matches!(error, InviteLinkError::Unknown(code) if code == "some_future_code"));
    }

    #[test]
    fn maps_not_found_with_legacy_body() {
        let error = map(
            404,
            r#"{"message":"Invite link not found.","validationErrors":null,"exceptionMessage":null,"exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"}"#,
        );
        assert!(matches!(error, InviteLinkError::LinkNotFound));
    }

    #[test]
    fn maps_not_found_with_empty_body() {
        assert!(matches!(map(404, ""), InviteLinkError::LinkNotFound));
    }

    #[test]
    fn keeps_legacy_bad_request_as_api_error() {
        let error = map(
            400,
            r#"{"message":"You're already a member of Acme.","validationErrors":null,"object":"error"}"#,
        );
        assert!(matches!(error, InviteLinkError::Api(ApiError::Response(_))));
    }

    #[test]
    fn keeps_model_binding_problem_as_api_error() {
        // ASP.NET's default validation problem uses plain strings rather than error codes.
        let error = map(
            400,
            r#"{"type":"https://tools.ietf.org/html/rfc9110#section-15.5.1","status":400,"errors":{"Code":["The Code field is required."]}}"#,
        );
        assert!(matches!(error, InviteLinkError::Api(ApiError::Response(_))));
    }

    #[test]
    fn keeps_other_statuses_as_api_error() {
        let error = map(
            500,
            &validation_problem("code", "already_organization_member"),
        );
        assert!(matches!(error, InviteLinkError::Api(ApiError::Response(_))));
    }

    #[test]
    fn keeps_transport_errors_as_api_error() {
        let error = map_accept_error(ApiError::from(std::io::Error::other("boom")));
        assert!(matches!(error, InviteLinkError::Api(ApiError::Io(_))));
    }
}
