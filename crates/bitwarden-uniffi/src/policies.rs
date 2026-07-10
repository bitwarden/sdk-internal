use bitwarden_policies::{
    EnrichedPolicy, OrganizationUserPolicyContext, PolicyClient, PolicyType, PolicyView,
};

/// Client for policy domain operations.
#[derive(uniffi::Object)]
pub struct PoliciesClient(pub(crate) PolicyClient);

#[uniffi::export]
impl PoliciesClient {
    /// Filter policies of the given type for the current user.
    /// POC code path that uses an enum to wrap strongly typed data and the policy definition.
    pub fn filter(
        &self,
        policies: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
        policy_type: PolicyType,
    ) -> Vec<EnrichedPolicy> {
        self.0
            .filter(policies, organization_user_policy_contexts, policy_type)
    }
}
