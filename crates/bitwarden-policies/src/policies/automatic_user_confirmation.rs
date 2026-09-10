use bitwarden_organizations::OrganizationUserType;

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Automatic User Confirmation policy.
pub struct AutomaticUserConfirmationPolicy;

impl Policy for AutomaticUserConfirmationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::AutomaticUserConfirmation
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::AutomaticUserConfirmation
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}
