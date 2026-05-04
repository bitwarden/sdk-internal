use bitwarden_organizations::ProfileOrganization;
use bitwarden_policies::{PolicyClient, PolicyView};

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
        organizations: Vec<ProfileOrganization>,
        policy_type: u8,
    ) -> Vec<PolicyView> {
        self.0.filter_by_type(policies, organizations, policy_type)
    }
}
