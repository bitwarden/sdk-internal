//! [`PolicyClient`] and its associated extension trait.

use std::collections::HashMap;

use bitwarden_core::Client;
use uuid::Uuid;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{EnrichedPolicy, OrganizationUserPolicyContext, PolicyType, PolicyView};

/// Client for policy domain operations.
///
/// Obtained via [`PoliciesClientExt::policies`] on a [`Client`].
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PolicyClient {}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl PolicyClient {
    /// Create a new PolicyClient instance.
    pub fn new() -> Self {
        Self {}
    }

    /// Filter policies of the given type for the current user.
    /// POC code path that uses an enum to wrap strongly typed data and the policy definition.
    pub fn filter(
        &self,
        policies: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
        policy_type: PolicyType,
    ) -> Vec<EnrichedPolicy> {
        let org_map: HashMap<Uuid, OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .into_iter()
                .map(|o| (o.id, o))
                .collect();

        policies
            .iter()
            .filter(|p| p.r#type == policy_type)
            .map(EnrichedPolicy::from_policy_view)
            .filter(|ep| ep.enforced(&org_map))
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
        PolicyClient {}
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use uuid::Uuid;

    use super::*;
    use crate::EnrichedPolicyType;

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

    #[test]
    fn filter_new_returns_matching_policy_type() {
        let org_id = Uuid::new_v4();
        let policies = vec![
            policy_view(org_id, PolicyType::MasterPassword, true),
            policy_view(org_id, PolicyType::PasswordGenerator, true),
        ];
        let orgs = vec![organization(org_id)];

        let client = PolicyClient::new();
        let result = client.filter(policies, orgs, PolicyType::MasterPassword);

        assert_eq!(result.len(), 1);
        assert!(matches!(
            result[0].r#type,
            EnrichedPolicyType::MasterPassword(_)
        ));
    }

    #[test]
    fn filter_returns_empty_for_no_match() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = vec![organization(org_id)];

        let client = PolicyClient::new();
        let result = client.filter(policies, orgs, PolicyType::TwoFactorAuthentication);

        assert!(result.is_empty());
    }

    #[test]
    fn filter_does_not_exempt_owner_from_master_password() {
        let org_id = Uuid::new_v4();
        // Master Password applies to everyone (its definition has no exempt roles),
        // so an Owner is still enforced.
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = vec![OrganizationUserPolicyContext {
            id: org_id,
            role: OrganizationUserType::Owner,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: true,
            is_provider_user: false,
        }];

        let client = PolicyClient::new();
        let result = client.filter(policies, orgs, PolicyType::MasterPassword);

        assert_eq!(result.len(), 1);
    }
}
