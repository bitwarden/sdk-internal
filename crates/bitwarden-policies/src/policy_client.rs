//! [`PolicyClient`] and its associated extension trait.

use std::collections::HashMap;

use bitwarden_core::{Client, OrganizationId};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    OrganizationUserPolicyContext, Policy, PolicyType, PolicyView,
    models::{EnforcedPolicy, EnforcedPolicyErased},
    policy::EnforceablePolicy,
};

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
    /// Creates a new [`PolicyClient`] with a freshly built registry.
    pub fn new() -> Self {
        Self
    }
}

/// FFI client
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl PolicyClient {
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = getManyEnforced))]
    pub fn get_many_enforced_erased(
        &self,
        policy_type: PolicyType,
        // TODO: policy_views and ctx should come from state rather than being specified by the
        // caller
        policy_views: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
    ) -> Vec<EnforcedPolicyErased> {
        let contexts: HashMap<OrganizationId, &OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .iter()
                .map(|ctx| (ctx.id, ctx))
                .collect();
        policy_type
            .to_policy()
            .get_many_enforced_erased(&policy_views, &contexts)
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = getEnforced))]
    pub fn get_enforced_erased(
        &self,
        policy_type: PolicyType,
        organization_id: OrganizationId,
        // TODO: policy_views and ctx should come from state rather than being specified by the
        // caller
        policy_views: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
    ) -> EnforcedPolicyErased {
        let contexts: HashMap<OrganizationId, &OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .iter()
                .map(|ctx| (ctx.id, ctx))
                .collect();
        policy_type
            .to_policy()
            .get_enforced_erased(organization_id, &policy_views, &contexts)
    }
}

/// Native rust client
impl PolicyClient {
    pub fn get_many_enforced<P: Policy>(
        &self,
        policy: P,
        // TODO: policy_views and ctx should come from state rather than being specified by the
        // caller
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<EnforcedPolicy<P>> {
        let contexts: HashMap<OrganizationId, &OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .iter()
                .map(|ctx| (ctx.id, ctx))
                .collect();
        policy_views
            .iter()
            .map(|p| policy.get_enforced(p.organization_id, policy_views, &contexts))
            .collect()
    }

    pub fn get_enforced<P: Policy>(
        &self,
        policy: P,
        organization_id: OrganizationId,
        // TODO: policy_views and ctx should come from state rather than being specified by the
        // caller
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> EnforcedPolicy<P> {
        let contexts: HashMap<OrganizationId, &OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .iter()
                .map(|ctx| (ctx.id, ctx))
                .collect();
        policy.get_enforced(organization_id, policy_views, &contexts)
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
    use crate::{MasterPasswordPolicy, MasterPasswordPolicyResponse, policy_type::PolicyDataType};

    fn policy_view(
        organization_id: OrganizationId,
        policy_type: PolicyType,
        data: Option<&str>,
    ) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: policy_type,
            data: data.map(str::to_owned),
            enabled: true,
            revision_date: None,
        }
    }

    /// A confirmed, non-provider member of `organization_id` that a policy applies to.
    fn confirmed_member(organization_id: OrganizationId) -> OrganizationUserPolicyContext {
        OrganizationUserPolicyContext {
            id: organization_id,
            status: OrganizationUserStatusType::Confirmed,
            role: OrganizationUserType::User,
            enabled: true,
            use_policies: true,
            is_provider_user: false,
        }
    }

    #[test]
    fn get_enforced_returns_typed_decision() {
        let org_id = OrganizationId::new_v4();
        let views = [policy_view(
            org_id,
            PolicyType::MasterPassword,
            Some(r#"{"minComplexity":3,"minLength":12}"#),
        )];
        let contexts = [confirmed_member(org_id)];

        let result =
            PolicyClient::new().get_enforced(MasterPasswordPolicy, org_id, &views, &contexts);

        assert_eq!(result.organization_id, org_id);
        assert!(result.enforced);
        assert_eq!(
            result.data,
            MasterPasswordPolicyResponse {
                min_complexity: Some(3),
                min_length: Some(12),
                ..Default::default()
            }
        );
    }

    #[test]
    fn get_many_enforced_returns_one_decision_per_view() {
        let org_id = OrganizationId::new_v4();
        let views = [policy_view(
            org_id,
            PolicyType::MasterPassword,
            Some(r#"{"minComplexity":3}"#),
        )];
        let contexts = [confirmed_member(org_id)];

        let results =
            PolicyClient::new().get_many_enforced(MasterPasswordPolicy, &views, &contexts);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].organization_id, org_id);
        assert!(results[0].enforced);
        assert_eq!(results[0].data.min_complexity, Some(3));
    }

    #[test]
    fn get_enforced_erased_returns_erased_decision() {
        let org_id = OrganizationId::new_v4();
        let views = vec![policy_view(
            org_id,
            PolicyType::MasterPassword,
            Some(r#"{"minComplexity":3}"#),
        )];
        let contexts = vec![confirmed_member(org_id)];

        let result = PolicyClient::new().get_enforced_erased(
            PolicyType::MasterPassword,
            org_id,
            views,
            contexts,
        );

        assert_eq!(result.organization_id, org_id);
        assert!(result.enforced);
        assert_eq!(
            result.data,
            PolicyDataType::MasterPassword(MasterPasswordPolicyResponse {
                min_complexity: Some(3),
                ..Default::default()
            })
        );
    }

    #[test]
    fn get_many_enforced_erased_returns_one_decision_per_view() {
        let org_id = OrganizationId::new_v4();
        let views = vec![policy_view(org_id, PolicyType::MasterPassword, None)];
        let contexts = vec![confirmed_member(org_id)];

        let results = PolicyClient::new().get_many_enforced_erased(
            PolicyType::MasterPassword,
            views,
            contexts,
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].organization_id, org_id);
        assert!(results[0].enforced);
        assert_eq!(
            results[0].data,
            PolicyDataType::MasterPassword(MasterPasswordPolicyResponse::default())
        );
    }
}
