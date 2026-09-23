use crate::{PolicyDefinition, PolicyType, policy_type::PolicyDataType};

/// Send Controls policy.
pub struct SendControlsPolicy;

impl PolicyDefinition for SendControlsPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::SendControls
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::SendControls
    }
}
