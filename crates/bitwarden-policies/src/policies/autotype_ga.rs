use crate::{PolicyDefinition, PolicyType, policy_type::PolicyDataType};

/// Autotype GA policy.
pub struct AutotypeGaPolicy;

impl PolicyDefinition for AutotypeGaPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::AutotypeGa
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::AutotypeGa
    }
}
