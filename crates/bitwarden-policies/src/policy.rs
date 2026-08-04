use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use serde::de::DeserializeOwned;

use crate::policy_type::{PolicyDataType, PolicyType};

/// Declares which organization members a specific policy type applies to.
///
/// An implementor identifies the [`PolicyType`] it handles and specifies the
/// role exemptions, applicable membership statuses, and provider exemption.
/// The defaults match the most common Bitwarden policy: exempt Owners and
/// Admins, exempt provider users, apply to Accepted and Confirmed members.
///
/// Ready-made implementations for the built-in policy types live in
/// [`policy_overrides`](crate::policy_overrides).
pub trait Policy: Send + Sync + 'static {
    /// Returns the policy type this definition handles.
    fn policy_type(&self) -> PolicyType;

    fn to_erased(&self, data: Self::Data) -> PolicyDataType;

    /// The strongly-typed data for this policy. The [`Default`] value is
    /// the fall-back whenever the policy is not enforced or the raw data could
    /// not be parsed.
    type Data: Default + DeserializeOwned;

    /// Returns the organization roles that are exempt from this policy.
    ///
    /// Defaults to [`Owner`](OrganizationUserType::Owner) and
    /// [`Admin`](OrganizationUserType::Admin).
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[OrganizationUserType::Owner, OrganizationUserType::Admin]
    }

    /// Returns whether provider users are exempt from this policy.
    ///
    /// Defaults to `true`.
    fn exempt_providers(&self) -> bool {
        true
    }

    /// Returns the organization membership statuses for which this policy applies.
    ///
    /// Defaults to [`Accepted`](OrganizationUserStatusType::Accepted) and
    /// [`Confirmed`](OrganizationUserStatusType::Confirmed).
    fn applicable_statuses(&self) -> &[OrganizationUserStatusType] {
        &[
            OrganizationUserStatusType::Accepted,
            OrganizationUserStatusType::Confirmed,
        ]
    }
}
