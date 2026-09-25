use crate::{PolicyDefinition, PolicyType, policy_type::PolicyDataType};

/// Single Organization policy.
pub struct SingleOrgPolicy;

impl PolicyDefinition for SingleOrgPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::SingleOrg
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::SingleOrg
    }
}
