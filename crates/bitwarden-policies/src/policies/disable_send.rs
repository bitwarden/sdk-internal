use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Disable Send policy.
pub struct DisableSendPolicy;

impl Policy for DisableSendPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::DisableSend
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::DisableSend
    }
}
