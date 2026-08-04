use bitwarden_core::OrganizationId;
use bitwarden_policies::{
    EnforcedPolicyErased, OrganizationUserPolicyContext, PolicyClient, PolicyType, PolicyView,
};

/// Client for policy domain operations.
#[derive(uniffi::Object)]
pub struct PoliciesClient(pub(crate) PolicyClient);

#[uniffi::export]
impl PoliciesClient {
    /// Evaluate whether the policy of the given type is enforced against the
    /// current user for a single organization.
    pub fn get_enforced(
        &self,
        policy_type: PolicyType,
        organization_id: OrganizationId,
        policy_views: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
    ) -> EnforcedPolicyErased {
        self.0.get_enforced_erased(
            policy_type,
            organization_id,
            policy_views,
            organization_user_policy_contexts,
        )
    }

    /// Evaluate whether the policy of the given type is enforced against the
    /// current user across all of their organizations.
    pub fn get_many_enforced(
        &self,
        policy_type: PolicyType,
        policy_views: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
    ) -> Vec<EnforcedPolicyErased> {
        self.0.get_many_enforced_erased(
            policy_type,
            policy_views,
            organization_user_policy_contexts,
        )
    }
}
