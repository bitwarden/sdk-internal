#![allow(dead_code)]

//! Policy filtering logic.
//!
//! Provides the [`PolicyDefinition`] trait for determining which policies
//! should be enforced against the current user based on business rules.

use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};

/// Defines the filtering behavior for a specific policy type.
///
/// Implement this trait to control how a policy is enforced.
pub trait PolicyDefinition: Send + Sync + 'static {
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

/// A default policy definition that will use the default enforcement rules.
/// Used where no policy-specific definition is provided.
pub(crate) struct DefaultPolicyDefinition;
impl PolicyDefinition for DefaultPolicyDefinition {}
