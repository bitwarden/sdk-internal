//! Custom policy implementations that override the default rules.

use bitwarden_organizations::OrganizationUserType;

use crate::filter::{Policy, PolicyType};

/// Master Password policy (type 1).
///
/// Applies to **everyone**, including Owners and Admins.
pub struct MasterPasswordPolicy;

impl Policy for MasterPasswordPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType(1)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Password Generator policy (type 2).
///
/// Applies to **everyone**, including Owners and Admins.
pub struct PasswordGeneratorPolicy;

impl Policy for PasswordGeneratorPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType(2)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Maximum Vault Timeout policy (type 9).
///
/// Applies to everyone **except Owners**. Admins are not exempt.
pub struct MaximumVaultTimeoutPolicy;

impl Policy for MaximumVaultTimeoutPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType(9)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[OrganizationUserType::Owner]
    }
}

/// Free Families Sponsorship policy (type 13).
///
/// Applies to **everyone**, including Owners and Admins.
pub struct FreeFamiliesSponsorshipPolicy;

impl Policy for FreeFamiliesSponsorshipPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType(13)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Remove Unlock with PIN policy (type 14).
///
/// Applies to **everyone**, including Owners and Admins.
pub struct RemoveUnlockWithPinPolicy;

impl Policy for RemoveUnlockWithPinPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType(14)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Restricted Item Types policy (type 15).
///
/// Applies to **everyone**, including Owners and Admins.
pub struct RestrictedItemTypesPolicy;

impl Policy for RestrictedItemTypesPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType(15)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Automatic User Confirmation policy (type 18).
///
/// Applies to **everyone**, including Owners and Admins.
pub struct AutomaticUserConfirmationPolicy;

impl Policy for AutomaticUserConfirmationPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType(18)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{
        OrganizationUserStatusType, OrganizationUserType, ProfileOrganization,
    };
    use uuid::Uuid;

    use super::*;
    use crate::filter::{PolicyFilter, PolicyView};

    fn policy_view(organization_id: Uuid, policy_type: u8) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: PolicyType(policy_type),
            data: None,
            enabled: true,
        }
    }

    fn org(id: Uuid, user_type: OrganizationUserType) -> ProfileOrganization {
        ProfileOrganization {
            id,
            r#type: user_type,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: true,
            is_provider_user: false,
            ..Default::default()
        }
    }

    // --- MasterPasswordPolicy ---

    #[test]
    fn master_password_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 1)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(MasterPasswordPolicy.filter(&policies, &orgs).len(), 1);
    }

    #[test]
    fn master_password_applies_to_admin() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 1)];
        let orgs = [org(org_id, OrganizationUserType::Admin)];
        assert_eq!(MasterPasswordPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- PasswordGeneratorPolicy ---

    #[test]
    fn password_generator_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 2)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(PasswordGeneratorPolicy.filter(&policies, &orgs).len(), 1);
    }

    #[test]
    fn password_generator_applies_to_admin() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 2)];
        let orgs = [org(org_id, OrganizationUserType::Admin)];
        assert_eq!(PasswordGeneratorPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- MaximumVaultTimeoutPolicy ---

    #[test]
    fn maximum_vault_timeout_exempts_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 9)];
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
        let policies = [policy_view(org_id, 9)];
        let orgs = [org(org_id, OrganizationUserType::Admin)];
        assert_eq!(MaximumVaultTimeoutPolicy.filter(&policies, &orgs).len(), 1);
    }

    #[test]
    fn maximum_vault_timeout_applies_to_user() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 9)];
        let orgs = [org(org_id, OrganizationUserType::User)];
        assert_eq!(MaximumVaultTimeoutPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- FreeFamiliesSponsorshipPolicy ---

    #[test]
    fn free_families_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 13)];
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
        let policies = [policy_view(org_id, 14)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(RemoveUnlockWithPinPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- RestrictedItemTypesPolicy ---

    #[test]
    fn restricted_item_types_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 15)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(RestrictedItemTypesPolicy.filter(&policies, &orgs).len(), 1);
    }

    // --- AutomaticUserConfirmationPolicy ---

    #[test]
    fn automatic_user_confirmation_applies_to_owner() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 18)];
        let orgs = [org(org_id, OrganizationUserType::Owner)];
        assert_eq!(
            AutomaticUserConfirmationPolicy
                .filter(&policies, &orgs)
                .len(),
            1
        );
    }
}
