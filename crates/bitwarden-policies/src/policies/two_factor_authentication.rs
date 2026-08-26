use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Two-factor Authentication policy.
pub struct TwoFactorAuthenticationPolicy;

impl Policy for TwoFactorAuthenticationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::TwoFactorAuthentication
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::TwoFactorAuthentication
    }
}
