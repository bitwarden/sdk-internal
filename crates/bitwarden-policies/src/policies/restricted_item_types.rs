use bitwarden_organizations::OrganizationUserType;

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Restricted Item Types policy.
pub struct RestrictedItemTypesPolicy;

impl Policy for RestrictedItemTypesPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::RestrictedItemTypes
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::RestrictedItemTypes
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}
