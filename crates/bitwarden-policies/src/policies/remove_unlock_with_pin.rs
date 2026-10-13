use bitwarden_organizations::OrganizationUserType;

use crate::{PolicyDefinition, PolicyType, policy_type::PolicyDataType};

/// Remove Unlock with PIN policy.
pub struct RemoveUnlockWithPinPolicy;

impl PolicyDefinition for RemoveUnlockWithPinPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::RemoveUnlockWithPin
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::RemoveUnlockWithPin
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}
