//! [`PolicyClient`] and its associated extension trait.

use bitwarden_core::Client;
use bitwarden_organizations::ProfileOrganization;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    filter::{PolicyType, PolicyView},
    registry::PolicyRegistry,
};

fn build_policy_registry() -> PolicyRegistry {
    // Policy definitions will be registered here in PM-34154
    PolicyRegistry::builder().build()
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
        organizations: Vec<ProfileOrganization>,
        policy_type: u8,
    ) -> Vec<PolicyView> {
        self.registry
            .filter_by_type(&policies, &organizations, PolicyType(policy_type))
            .into_iter()
            .cloned()
            .collect()
    }
}

/// Extension trait that adds a [`policies`](PoliciesClientExt::policies) method to [`Client`].
#[allow(missing_docs)]
pub trait PoliciesClientExt {
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

    fn policy_view(organization_id: Uuid, policy_type: u8, enabled: bool) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: PolicyType(policy_type),
            data: None,
            enabled,
        }
    }

    fn organization(id: Uuid) -> ProfileOrganization {
        ProfileOrganization {
            id,
            r#type: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: true,
            is_provider_user: false,
            ..Default::default()
        }
    }

    #[test]
    fn filter_by_type_delegates_to_registry() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, 1, true), policy_view(org_id, 2, true)];
        let orgs = vec![organization(org_id)];

        let client = PolicyClient::new();
        let result = client.filter_by_type(policies, orgs, 1);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].r#type, PolicyType(1));
    }

    #[test]
    fn filter_by_type_returns_empty_for_no_match() {
        let org_id = Uuid::new_v4();
        let policies = vec![policy_view(org_id, 1, true)];
        let orgs = vec![organization(org_id)];

        let client = PolicyClient::new();
        let result = client.filter_by_type(policies, orgs, 99);

        assert!(result.is_empty());
    }

    #[test]
    fn filter_by_type_uses_registered_policy_definition() {
        struct NoExemptionPolicy;
        impl Policy for NoExemptionPolicy {
            fn policy_type(&self) -> PolicyType {
                PolicyType(1)
            }
            fn exempt_roles(&self) -> &[OrganizationUserType] {
                &[]
            }
        }

        let org_id = Uuid::new_v4();
        // Owner — normally exempt, but NoExemptionPolicy removes the exemption
        let policies = vec![policy_view(org_id, 1, true)];
        let orgs = vec![ProfileOrganization {
            id: org_id,
            r#type: OrganizationUserType::Owner,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: true,
            is_provider_user: false,
            ..Default::default()
        }];

        let registry = PolicyRegistry::builder()
            .register(NoExemptionPolicy)
            .build();
        let client = PolicyClient { registry };
        let result = client.filter_by_type(policies, orgs, 1);

        assert_eq!(result.len(), 1);
    }
}
