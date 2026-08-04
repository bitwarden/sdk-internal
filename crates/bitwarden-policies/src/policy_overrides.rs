//! Custom policy implementations that override the default rules.

use bitwarden_organizations::OrganizationUserType;

use crate::{MasterPasswordPolicyResponse, Policy, PolicyType, policy_type::PolicyDataType};

/// Master Password policy (type 1).
///
/// Applies to **everyone**, including Owners and Admins.
pub struct MasterPasswordPolicy;

impl Policy for MasterPasswordPolicy {
    type Data = MasterPasswordPolicyResponse;

    fn policy_type(&self) -> PolicyType {
        PolicyType::MasterPassword
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::MasterPassword(data)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Password Generator policy.
///
/// Applies to **everyone**, including Owners and Admins.
pub struct PasswordGeneratorPolicy;

impl Policy for PasswordGeneratorPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::PasswordGenerator
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::PasswordGenerator
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Maximum Vault Timeout policy.
///
/// Applies to everyone **except Owners**. Admins are not exempt.
pub struct MaximumVaultTimeoutPolicy;

impl Policy for MaximumVaultTimeoutPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::MaximumVaultTimeout
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::MaximumVaultTimeout
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[OrganizationUserType::Owner]
    }
}

/// Free Families Sponsorship policy.
///
/// Applies to **everyone**, including Owners and Admins.
pub struct FreeFamiliesSponsorshipPolicy;

impl Policy for FreeFamiliesSponsorshipPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::FreeFamiliesSponsorship
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::FreeFamiliesSponsorship
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Remove Unlock with PIN policy.
///
/// Applies to **everyone**, including Owners and Admins.
pub struct RemoveUnlockWithPinPolicy;

impl Policy for RemoveUnlockWithPinPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::RemoveUnlockWithPin
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::RemoveUnlockWithPin
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Restricted Item Types policy.
///
/// Applies to **everyone**, including Owners and Admins.
pub struct RestrictedItemTypesPolicy;

impl Policy for RestrictedItemTypesPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::RestrictedItemTypes
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::RestrictedItemTypes
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Automatic User Confirmation policy.
///
/// Applies to **everyone**, including Owners and Admins.
pub struct AutomaticUserConfirmationPolicy;

impl Policy for AutomaticUserConfirmationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::AutomaticUserConfirmation
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::AutomaticUserConfirmation
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Organization User Notification policy.
///
/// Applies to **everyone**, including Owners and Admins.
pub struct OrganizationUserNotificationPolicy;

impl Policy for OrganizationUserNotificationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::OrganizationUserNotification
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::OrganizationUserNotification
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}
