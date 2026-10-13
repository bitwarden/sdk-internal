use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::invite::InviteKeyBundleError;
use http::StatusCode;
use thiserror::Error;

use crate::validation_problem::{ValidationError, ValidationProblem};

/// Errors returned from invite link client operations, except accepting an invite (see
/// [`AcceptInviteLinkError`]).
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum InviteLinkError {
    /// A cryptographic invite operation (creating, unsealing, or recovering the invite) failed.
    #[error(transparent)]
    Invite(#[from] InviteKeyBundleError),
    /// A network request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A low-level cryptographic operation (key wrapping, encapsulation, or public-key parsing)
    /// failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A required field was missing from a server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A value was present but malformed and could not be parsed.
    #[error("Failed to parse `{0}`")]
    ParseFailure(&'static str),
    /// No allowed domains were specified.
    #[error("At least one allowed domain is required.")]
    NoAllowedDomains,
}

/// Errors returned from [`crate::InviteLinkUserClient::accept_and_optionally_confirm`].
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum AcceptInviteLinkError {
    /// A cryptographic invite operation (unsealing the invite key or organization key) failed.
    #[error(transparent)]
    Invite(#[from] InviteKeyBundleError),
    /// A network request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A low-level cryptographic operation (key encapsulation, encryption, or public-key parsing)
    /// failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A required field was missing from a server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// A value was present but malformed and could not be parsed.
    #[error("Failed to parse `{0}`")]
    ParseFailure(&'static str),
    /// The account-recovery public key returned by the server does not match the organization
    /// public key bound into the invite.
    #[error("Account recovery public key does not match the invite's bound organization key")]
    RecoveryKeyMismatch,

    // Server-reported failures when accepting or confirming an invite link, mapped from the
    // server's error responses by `AcceptInviteLinkError::from_api_error`.
    /// The invite link does not exist, its code does not match, or the organization is disabled.
    #[error("The invite link was not found")]
    LinkNotFound,
    /// The organization's plan does not support invite links.
    #[error("The organization's plan does not support invite links")]
    InviteLinkNotAvailable,
    /// The invite link does not support self-confirmation.
    #[error("The invite link does not support confirmation")]
    InviteLinkConfirmationNotSupported,
    /// The user must verify their email address before joining the organization.
    #[error("The user's email address is not verified")]
    EmailNotVerified,
    /// The user's email domain is not in the invite link's allowed domains.
    #[error("The user's email domain is not allowed by the invite link")]
    EmailDomainNotAllowed,
    /// Provider users cannot join organizations via invite links.
    #[error("Provider users cannot join organizations via invite link")]
    ProviderUsersCannotJoin,
    /// The user's access to the organization has been revoked.
    #[error("The user's access to the organization has been revoked")]
    OrganizationAccessRevoked,
    /// The user is already a confirmed member of the organization.
    #[error("The user is already a member of the organization")]
    AlreadyOrganizationMember,
    /// The organization has no available seats.
    #[error("The organization has no available seats")]
    OrganizationHasNoAvailableSeats,
    /// The server was unable to add a seat for the user.
    #[error("Unable to add a seat for the user")]
    SeatAddFailed,
    /// The organization requires account recovery enrollment, but no reset password key was sent.
    #[error("Account recovery enrollment is required")]
    ResetPasswordKeyRequired,
    /// The organization's Single Organization policy requires the user to leave all other
    /// organizations first.
    #[error("The user must leave all other organizations before joining")]
    MemberOfAnotherOrganization,
    /// The user belongs to another organization whose Single Organization policy forbids joining.
    #[error("A Single Organization policy prevents joining")]
    SingleOrganizationPolicy,
    /// The organization requires two-step login, which the user has not enabled.
    #[error("Two-step login is required to join the organization")]
    TwoFactorRequiredForMembership,
    /// The user is already an admin of a free organization.
    #[error("The user can only be an admin of one free organization")]
    OnlyOneFreeOrganizationAdminAllowed,
    /// The server returned a validation error code this SDK version does not recognize. Carries
    /// the server's human-readable English description of the error, suitable for display; the
    /// unrecognized code itself is logged.
    #[error("{0}")]
    Unknown(String),
}

/// Displayed for an unrecognized error code when the server provides no `detail` for it.
const UNKNOWN_ERROR_FALLBACK_DETAIL: &str = "An unexpected error occurred.";

impl AcceptInviteLinkError {
    /// Maps an error from an invite link endpoint (fetching the invite, accepting, or confirming)
    /// onto an [`AcceptInviteLinkError`].
    ///
    /// A `400` [`ValidationProblem`] maps to the variant matching its error code. Responses in the
    /// legacy error format carry no code and are left as [`AcceptInviteLinkError::Api`] so existing
    /// clients that inspect the raw response keep working. A `404` always maps to
    /// [`AcceptInviteLinkError::LinkNotFound`], regardless of body shape.
    ///
    /// Only use this for those endpoints: a `404` is interpreted as the invite link not existing.
    pub(crate) fn from_api_error(error: ApiError) -> Self {
        if let ApiError::Response(content) = &error
            && content.status == StatusCode::NOT_FOUND
        {
            return Self::LinkNotFound;
        }

        match ValidationProblem::from_api_error(&error)
            .and_then(ValidationProblem::into_first_error)
        {
            Some(error) => Self::from_validation_error(error),
            None => Self::Api(error),
        }
    }

    fn from_validation_error(error: ValidationError) -> Self {
        match error.code.as_str() {
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
            code => {
                tracing::warn!(code, "Unrecognized invite link error code");
                Self::Unknown(
                    error
                        .detail
                        .unwrap_or_else(|| UNKNOWN_ERROR_FALLBACK_DETAIL.to_owned()),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation_problem::tests::{response_error, validation_problem};

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
    fn maps_unmapped_code_to_unknown_with_detail() {
        let error = map(400, &validation_problem("code", "some_future_code"));
        assert!(
            matches!(&error, AcceptInviteLinkError::Unknown(detail) if detail == "Some detail.")
        );
        assert_eq!(error.to_string(), "Some detail.");
    }

    #[test]
    fn maps_unmapped_code_without_detail_to_unknown_with_fallback() {
        let error = map(
            400,
            r#"{"type":"validation_error","status":400,"errors":{"code":[{"type":"some_future_code"}]}}"#,
        );
        assert!(
            matches!(error, AcceptInviteLinkError::Unknown(detail) if detail == UNKNOWN_ERROR_FALLBACK_DETAIL)
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
