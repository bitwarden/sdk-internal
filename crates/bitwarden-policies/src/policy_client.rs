//! [`PolicyClient`] and its associated extension trait.

use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    OrganizationUserPolicyContext, PolicyType, PolicyView, policy_overrides::*,
    registry::PolicyRegistry,
};

fn build_policy_registry() -> PolicyRegistry {
    PolicyRegistry::builder()
        .register(MasterPasswordPolicy)
        .register(PasswordGeneratorPolicy)
        .register(MaximumVaultTimeoutPolicy)
        .register(FreeFamiliesSponsorshipPolicy)
        .register(RemoveUnlockWithPinPolicy)
        .register(RestrictedItemTypesPolicy)
        .register(AutomaticUserConfirmationPolicy)
        .build()
}

/// Client for policy domain operations.
///
/// Obtained via [`PoliciesClientExt::policies`] on a [`Client`].
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PolicyClient {
    registry: PolicyRegistry,
}

impl Default for PolicyClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyClient {
    /// Creates a new [`PolicyClient`] with a freshly built registry.
    pub fn new() -> Self {
        Self {
            registry: build_policy_registry(),
        }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl PolicyClient {
    /// Filter policies of the given type for the current user.
    ///
    /// Untyped FFI path: native/WASM callers pass a runtime `policy_type` integer.
    /// Delegates to the registry, falling back to default rules for unknown types.
    pub fn filter_by_type(
        &self,
        policies: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
        policy_type: PolicyType,
    ) -> Vec<PolicyView> {
        self.registry
            .filter_by_type(&policies, &organization_user_policy_contexts, policy_type)
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

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use uuid::Uuid;

    use super::*;
    use crate::filter::Policy;

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
    fn filter_by_type_delegates_to_registry() {
        let org_id = Uuid::new_v4();
        let policies = vec![
            policy_view(org_id, PolicyType::MasterPassword, true),
            policy_view(org_id, PolicyType::PasswordGenerator, true),
        ];
        let orgs = vec![organization(org_id)];

        let client = PolicyClient::new();
        let result = client.filter_by_type(policies, orgs, PolicyType::MasterPassword);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].r#type, PolicyType::MasterPassword);
    }

    #[test]
    fn filter_by_type_returns_empty_for_no_match() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = vec![organization(org_id)];

        let client = PolicyClient::new();
        let result = client.filter_by_type(policies, orgs, PolicyType::TwoFactorAuthentication);

        assert!(result.is_empty());
    }

    #[test]
    fn filter_by_type_uses_registered_policy_definition() {
        struct NoExemptionPolicy;
        impl Policy for NoExemptionPolicy {
            fn policy_type(&self) -> PolicyType {
                PolicyType::MasterPassword
            }
            fn exempt_roles(&self) -> &[OrganizationUserType] {
                &[]
            }
        }

        let org_id = Uuid::new_v4();
        // Owner — normally exempt, but NoExemptionPolicy removes the exemption
        let policies = vec![policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = vec![OrganizationUserPolicyContext {
            id: org_id,
            role: OrganizationUserType::Owner,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: true,
            is_provider_user: false,
        }];

        let registry = PolicyRegistry::builder()
            .register(NoExemptionPolicy)
            .build();
        let client = PolicyClient { registry };
        let result = client.filter_by_type(policies, orgs, PolicyType::MasterPassword);

        assert_eq!(result.len(), 1);
    }
}
