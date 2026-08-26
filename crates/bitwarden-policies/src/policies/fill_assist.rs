use bitwarden_organizations::OrganizationUserType;

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Fill Assist policy.
pub struct FillAssistPolicy;

impl Policy for FillAssistPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::FillAssist
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::FillAssist
    }
}
