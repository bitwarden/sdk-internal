use bitwarden_policies::{OrganizationUserPolicyContext, PolicyClient, PolicyType, PolicyView};

/// Client for policy domain operations.
#[derive(uniffi::Object)]
pub struct PoliciesClient(pub(crate) PolicyClient);

#[uniffi::export]
impl PoliciesClient {
    /// Filter policies of the given type for the current user.
    ///
    /// Returns the subset of `policies` that should be enforced against the user,
    /// based on their organization memberships and roles.
    pub fn filter_by_type(
        &self,
        policies: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
        policy_type: PolicyType,
    ) -> Vec<PolicyView> {
        self.0
            .filter_by_type(policies, organization_user_policy_contexts, policy_type)
    }
}
