//! [`PolicyClient`] and its associated extension trait.

use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{OrganizationUserPolicyContext, PolicyType, PolicyView};

/// Client for policy domain operations.
///
/// Obtained via [`PoliciesClientExt::policies`] on a [`Client`].
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PolicyClient;

impl Default for PolicyClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyClient {
    /// Creates a new [`PolicyClient`].
    pub fn new() -> Self {
        Self
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl PolicyClient {
    /// Filter policies of the given type for the current user.
    ///
    /// Untyped FFI path: native/WASM callers pass a runtime `policy_type` integer.
    /// Dispatches to the resolved [`crate::Policy`] for that type.
    pub fn filter_by_type(
        &self,
        policies: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
        policy_type: PolicyType,
    ) -> Vec<PolicyView> {
        policy_type
            .resolve_policy()
            .filter(&policies, &organization_user_policy_contexts)
            .into_iter()
            .cloned()
            .collect()
    }
}

/// Extension trait that adds a [`policies`](PoliciesClientExt::policies) method to [`Client`].
pub trait PoliciesClientExt {
    /// Creates a new [PolicyClient] instance.
    fn policies(&self) -> PolicyClient;
}

impl PoliciesClientExt for Client {
    fn policies(&self) -> PolicyClient {
        PolicyClient::new()
    }
}

/// Behavioral coverage for [`PolicyClient::filter_by_type`]. Tested at the client level
/// to ensure no change in behavior during refactors.
#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use uuid::Uuid;

    use super::*;

    fn policy_view(organization_id: Uuid, policy_type: PolicyType, enabled: bool) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: policy_type,
            data: None,
            enabled,
            revision_date: Default::default(),
        }
    }

    /// A confirmed, enabled, non-provider `User` — the baseline a policy applies to. Gate tests
    /// vary a single field via struct-update, e.g. `OrganizationUserPolicyContext { enabled:
    /// false, ..organization(org) }`.
    fn organization(id: Uuid) -> OrganizationUserPolicyContext {
        OrganizationUserPolicyContext {
            id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: true,
            is_provider_user: false,
        }
    }

    fn filter(
        policies: Vec<PolicyView>,
        orgs: Vec<OrganizationUserPolicyContext>,
        policy_type: PolicyType,
    ) -> Vec<PolicyView> {
        PolicyClient::new().filter_by_type(policies, orgs, policy_type)
    }

    #[test]
    fn keeps_a_matching_enabled_policy_and_filters_to_the_requested_type() {
        let org_id = Uuid::new_v4();
        let policies = vec![
            policy_view(org_id, PolicyType::MasterPassword, true),
            policy_view(org_id, PolicyType::PasswordGenerator, true),
        ];

        let result = filter(
            policies,
            vec![organization(org_id)],
            PolicyType::MasterPassword,
        );

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].r#type, PolicyType::MasterPassword);
    }

    #[test]
    fn returns_empty_when_no_policy_of_the_requested_type_exists() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = filter(
            policies,
            vec![organization(org_id)],
            PolicyType::TwoFactorAuthentication,
        );

        assert!(result.is_empty());
    }

    #[test]
    fn drops_a_disabled_policy() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, false)];

        let result = filter(
            policies,
            vec![organization(org_id)],
            PolicyType::MasterPassword,
        );

        assert!(result.is_empty());
    }

    #[test]
    fn drops_the_policy_when_the_organization_is_disabled() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = vec![OrganizationUserPolicyContext {
            enabled: false,
            ..organization(org_id)
        }];

        let result = filter(policies, orgs, PolicyType::MasterPassword);

        assert!(result.is_empty());
    }

    #[test]
    fn drops_the_policy_when_the_organization_does_not_support_policies() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = vec![OrganizationUserPolicyContext {
            use_policies: false,
            ..organization(org_id)
        }];

        let result = filter(policies, orgs, PolicyType::MasterPassword);

        assert!(result.is_empty());
    }

    #[test]
    fn drops_the_policy_for_a_provider_user() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = vec![OrganizationUserPolicyContext {
            is_provider_user: true,
            ..organization(org_id)
        }];

        let result = filter(policies, orgs, PolicyType::MasterPassword);

        assert!(result.is_empty());
    }

    #[test]
    fn drops_the_policy_for_non_applicable_membership_statuses() {
        let org_id = Uuid::new_v4();
        for status in [
            OrganizationUserStatusType::Invited,
            OrganizationUserStatusType::Revoked,
            OrganizationUserStatusType::Staged,
        ] {
            let label = format!("expected {status:?} to be dropped");
            let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
            let orgs = vec![OrganizationUserPolicyContext {
                status,
                ..organization(org_id)
            }];

            let result = filter(policies, orgs, PolicyType::MasterPassword);

            assert!(result.is_empty(), "{label}");
        }
    }

    #[test]
    fn keeps_the_policy_for_applicable_membership_statuses() {
        let org_id = Uuid::new_v4();
        for status in [
            OrganizationUserStatusType::Accepted,
            OrganizationUserStatusType::Confirmed,
        ] {
            let label = format!("expected {status:?} to be kept");
            let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
            let orgs = vec![OrganizationUserPolicyContext {
                status,
                ..organization(org_id)
            }];

            let result = filter(policies, orgs, PolicyType::MasterPassword);

            assert_eq!(result.len(), 1, "{label}");
        }
    }

    #[test]
    fn enforces_the_policy_by_default_when_the_org_is_absent_from_the_contexts() {
        let org_a = Uuid::new_v4();
        let org_b = Uuid::new_v4();
        let policies = vec![policy_view(org_a, PolicyType::MasterPassword, true)];

        // Only a context for a different org is provided.
        let result = filter(
            policies,
            vec![organization(org_b)],
            PolicyType::MasterPassword,
        );

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn enforces_the_policy_by_default_when_the_contexts_are_empty() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = filter(policies, vec![], PolicyType::MasterPassword);

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn applies_master_password_to_an_owner() {
        // MasterPasswordPolicy has no exempt roles, so it applies even to an Owner.
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = vec![OrganizationUserPolicyContext {
            role: OrganizationUserType::Owner,
            ..organization(org_id)
        }];

        let result = filter(policies, orgs, PolicyType::MasterPassword);

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn exempts_an_owner_from_maximum_vault_timeout() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MaximumVaultTimeout, true)];
        let orgs = vec![OrganizationUserPolicyContext {
            role: OrganizationUserType::Owner,
            ..organization(org_id)
        }];

        let result = filter(policies, orgs, PolicyType::MaximumVaultTimeout);

        assert!(result.is_empty());
    }

    #[test]
    fn applies_maximum_vault_timeout_to_admins_and_users() {
        let org_id = Uuid::new_v4();
        for role in [OrganizationUserType::Admin, OrganizationUserType::User] {
            let label = format!("expected {role:?} to be subject");
            let policies = vec![policy_view(org_id, PolicyType::MaximumVaultTimeout, true)];
            let orgs = vec![OrganizationUserPolicyContext {
                role,
                ..organization(org_id)
            }];

            let result = filter(policies, orgs, PolicyType::MaximumVaultTimeout);

            assert_eq!(result.len(), 1, "{label}");
        }
    }

    #[test]
    fn unregistered_policy_type_exempts_owners_and_admins_via_default_rules() {
        // TwoFactorAuthentication has no registered policy, so it falls back to the default rules:
        // exempt roles [Owner, Admin].
        let org_id = Uuid::new_v4();
        for role in [OrganizationUserType::Owner, OrganizationUserType::Admin] {
            let label = format!("expected {role:?} to be exempt");
            let policies = vec![policy_view(
                org_id,
                PolicyType::TwoFactorAuthentication,
                true,
            )];
            let orgs = vec![OrganizationUserPolicyContext {
                role,
                ..organization(org_id)
            }];

            let result = filter(policies, orgs, PolicyType::TwoFactorAuthentication);

            assert!(result.is_empty(), "{label}");
        }
    }

    #[test]
    fn unregistered_policy_type_applies_to_a_regular_user_via_default_rules() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(
            org_id,
            PolicyType::TwoFactorAuthentication,
            true,
        )];

        let result = filter(
            policies,
            vec![organization(org_id)],
            PolicyType::TwoFactorAuthentication,
        );

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filters_independently_across_multiple_organizations() {
        // org_a's member is a subject User; org_b's member is an Owner, exempt from
        // MaximumVaultTimeout.
        let org_a = Uuid::new_v4();
        let org_b = Uuid::new_v4();
        let policies = vec![
            policy_view(org_a, PolicyType::MaximumVaultTimeout, true),
            policy_view(org_b, PolicyType::MaximumVaultTimeout, true),
        ];
        let orgs = vec![
            organization(org_a),
            OrganizationUserPolicyContext {
                role: OrganizationUserType::Owner,
                ..organization(org_b)
            },
        ];

        let result = filter(policies, orgs, PolicyType::MaximumVaultTimeout);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].organization_id, org_a);
    }
}
