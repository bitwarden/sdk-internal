use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::invite::InviteKeyBundleError;
use thiserror::Error;

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
    // server's error responses in the `server_error` module.
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
    /// The server returned a validation error code this SDK version does not recognize.
    #[error("Unrecognized invite link error code `{0}`")]
    Unknown(String),
}
