use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Send Controls policy.
pub struct SendControlsPolicy;

impl Policy for SendControlsPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::SendControls
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::SendControls
    }
}
