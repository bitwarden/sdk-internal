//! Maps server error responses from the invite link endpoints (fetching the invite, accepting, and
//! confirming) onto typed [`AcceptInviteLinkError`] variants.
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
//! [`AcceptInviteLinkError::Api`] so existing clients that inspect the raw response keep working. A
//! `404` always maps to [`AcceptInviteLinkError::LinkNotFound`], regardless of body shape.

use std::collections::HashMap;

use bitwarden_core::ApiError;
use serde::Deserialize;

use crate::AcceptInviteLinkError;

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

impl ValidationProblem {
    /// Returns the first error code from a validation problem body, or `None` if the body is not a
    /// validation problem (e.g. the legacy error format).
    fn first_code(body: &str) -> Option<String> {
        let problem: Self = serde_json::from_str(body).ok()?;
        problem
            .errors
            .into_values()
            .flatten()
            .next()
            .map(|error| error.code)
    }
}

impl AcceptInviteLinkError {
    /// Maps an error from an invite link endpoint (fetching the invite, accepting, or confirming)
    /// onto an [`AcceptInviteLinkError`].
    ///
    /// Only use this for those endpoints: a `404` is interpreted as the invite link not existing.
    pub(crate) fn from_api_error(error: ApiError) -> Self {
        let ApiError::Response(content) = &error else {
            return Self::Api(error);
        };

        match content.status.as_u16() {
            404 => Self::LinkNotFound,
            400 => match ValidationProblem::first_code(&content.message) {
                Some(code) => Self::from_code(code),
                None => Self::Api(error),
            },
            _ => Self::Api(error),
        }
    }

    fn from_code(code: String) -> Self {
        match code.as_str() {
            "invite_link_not_available" => Self::InviteLinkNotAvailable,
            "invite_link_confirmation_not_supported" => Self::InviteLinkConfirmationNotSupported,
            "email_not_verified" => Self::EmailNotVerified,
            "email_domain_not_allowed" => Self::EmailDomainNotAllowed,
            "provider_users_cannot_join" => Self::ProviderUsersCannotJoin,
            "organization_access_revoked" => Self::OrganizationAccessRevoked,
            "already_organization_member" => Self::AlreadyOrganizationMember,
            "organization_has_no_available_seats" => Self::OrganizationHasNoAvailableSeats,
            "seat_add_failed" => Self::SeatAddFailed,
            "reset_password_key_required" => Self::ResetPasswordKeyRequired,
            "member_of_another_organization" => Self::MemberOfAnotherOrganization,
            "single_organization_policy" => Self::SingleOrganizationPolicy,
            "two_factor_required_for_membership" => Self::TwoFactorRequiredForMembership,
            "only_one_free_organization_admin_allowed" => Self::OnlyOneFreeOrganizationAdminAllowed,
            _ => Self::Unknown(code),
        }
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

    fn map(status: u16, body: &str) -> AcceptInviteLinkError {
        AcceptInviteLinkError::from_api_error(response_error(status, body))
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
                !matches!(
                    error,
                    AcceptInviteLinkError::Unknown(_) | AcceptInviteLinkError::Api(_)
                ),
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
        assert!(matches!(
            error,
            AcceptInviteLinkError::AlreadyOrganizationMember
        ));
    }

    #[test]
    fn maps_email_not_verified() {
        let error = map(
            400,
            &validation_problem("organizationId", "email_not_verified"),
        );
        assert!(matches!(error, AcceptInviteLinkError::EmailNotVerified));
    }

    #[test]
    fn maps_unmapped_code_to_unknown() {
        let error = map(400, &validation_problem("code", "some_future_code"));
        assert!(
            matches!(error, AcceptInviteLinkError::Unknown(code) if code == "some_future_code")
        );
    }

    #[test]
    fn maps_not_found_with_legacy_body() {
        let error = map(
            404,
            r#"{"message":"Invite link not found.","validationErrors":null,"exceptionMessage":null,"exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"}"#,
        );
        assert!(matches!(error, AcceptInviteLinkError::LinkNotFound));
    }

    #[test]
    fn maps_not_found_with_empty_body() {
        assert!(matches!(map(404, ""), AcceptInviteLinkError::LinkNotFound));
    }

    #[test]
    fn keeps_legacy_bad_request_as_api_error() {
        let error = map(
            400,
            r#"{"message":"You're already a member of Acme.","validationErrors":null,"object":"error"}"#,
        );
        assert!(matches!(
            error,
            AcceptInviteLinkError::Api(ApiError::Response(_))
        ));
    }

    #[test]
    fn keeps_model_binding_problem_as_api_error() {
        // ASP.NET's default validation problem uses plain strings rather than error codes.
        let error = map(
            400,
            r#"{"type":"https://tools.ietf.org/html/rfc9110#section-15.5.1","status":400,"errors":{"Code":["The Code field is required."]}}"#,
        );
        assert!(matches!(
            error,
            AcceptInviteLinkError::Api(ApiError::Response(_))
        ));
    }

    #[test]
    fn keeps_other_statuses_as_api_error() {
        let error = map(
            500,
            &validation_problem("code", "already_organization_member"),
        );
        assert!(matches!(
            error,
            AcceptInviteLinkError::Api(ApiError::Response(_))
        ));
    }

    #[test]
    fn keeps_transport_errors_as_api_error() {
        let error =
            AcceptInviteLinkError::from_api_error(ApiError::from(std::io::Error::other("boom")));
        assert!(matches!(error, AcceptInviteLinkError::Api(ApiError::Io(_))));
    }
}
