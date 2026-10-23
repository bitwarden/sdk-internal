use crate::{PolicyDefinition, PolicyType, policy_type::PolicyDataType};

pub struct AutotypeGaPolicy;

impl PolicyDefinition for AutotypeGaPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::AutotypeGaPolicy
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::AutotypeGaPolicy
    }
}
