//! Custom policy implementations that override the default rules.

use bitwarden_organizations::OrganizationUserType;

use crate::{PolicyType, filter::Policy};

/// Master Password policy (type 1).
///
/// Applies to **everyone**, including Owners and Admins.
pub struct MasterPasswordPolicy;

impl Policy for MasterPasswordPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::MasterPassword
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
    fn policy_type(&self) -> PolicyType {
        PolicyType::PasswordGenerator
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
    fn policy_type(&self) -> PolicyType {
        PolicyType::MaximumVaultTimeout
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
    fn policy_type(&self) -> PolicyType {
        PolicyType::FreeFamiliesSponsorshipPolicy
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
    fn policy_type(&self) -> PolicyType {
        PolicyType::RemoveUnlockWithPin
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
    fn policy_type(&self) -> PolicyType {
        PolicyType::RestrictedItemTypes
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
    fn policy_type(&self) -> PolicyType {
        PolicyType::AutomaticUserConfirmation
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use uuid::Uuid;

    use super::*;
    use crate::{PolicyOrganizationContext, PolicyView, filter::PolicyFilter};

    fn policy_view(organization_id: Uuid, policy_type: PolicyType) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: policy_type,
            data: None,
            enabled: true,
            revision_date: Default::default(),
        }
    }

    fn org(id: Uuid, user_type: OrganizationUserType) -> PolicyOrganizationContext {
        PolicyOrganizationContext {
            id,
            role: user_type,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: true,
            is_provider_user: false,
        }
    }

    // --- MasterPasswordPolicy ---

    #[test]
    fn master_password_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(MasterPasswordPolicy.filter(&policies, &orgs).len(), 1);
    }

    #[test]
    fn master_password_applies_to_admin() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword)];
        let orgs = [org(org_id, OrganizationUserType::Admin)];
        assert_eq!(MasterPasswordPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- PasswordGeneratorPolicy ---

    #[test]
    fn password_generator_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::PasswordGenerator)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(PasswordGeneratorPolicy.filter(&policies, &orgs).len(), 1);
    }

    #[test]
    fn password_generator_applies_to_admin() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::PasswordGenerator)];
        let orgs = [org(org_id, OrganizationUserType::Admin)];
        assert_eq!(PasswordGeneratorPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- MaximumVaultTimeoutPolicy ---

    #[test]
    fn maximum_vault_timeout_exempts_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MaximumVaultTimeout)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert!(
            MaximumVaultTimeoutPolicy
                .filter(&policies, &orgs)
                .is_empty()
        );
    }

    #[test]
    fn maximum_vault_timeout_applies_to_admin() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MaximumVaultTimeout)];
        let orgs = [org(org_id, OrganizationUserType::Admin)];
        assert_eq!(MaximumVaultTimeoutPolicy.filter(&policies, &orgs).len(), 1);
    }

    #[test]
    fn maximum_vault_timeout_applies_to_user() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MaximumVaultTimeout)];
        let orgs = [org(org_id, OrganizationUserType::User)];
        assert_eq!(MaximumVaultTimeoutPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- FreeFamiliesSponsorshipPolicy ---

    #[test]
    fn free_families_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(
            org_id,
            PolicyType::FreeFamiliesSponsorshipPolicy,
        )];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(
            FreeFamiliesSponsorshipPolicy.filter(&policies, &orgs).len(),
            1
        );
    }

    // --- RemoveUnlockWithPinPolicy ---

    #[test]
    fn remove_unlock_with_pin_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::RemoveUnlockWithPin)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(RemoveUnlockWithPinPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- RestrictedItemTypesPolicy ---

    #[test]
    fn restricted_item_types_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::RestrictedItemTypes)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(RestrictedItemTypesPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- AutomaticUserConfirmationPolicy ---

    #[test]
    fn automatic_user_confirmation_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::AutomaticUserConfirmation)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(
            AutomaticUserConfirmationPolicy
                .filter(&policies, &orgs)
                .len(),
            1
        );
    }
}
