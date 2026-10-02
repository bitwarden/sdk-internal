use crate::{PolicyDefinition, PolicyType, policy_type::PolicyDataType};

/// Two-factor Authentication policy.
pub struct TwoFactorAuthenticationPolicy;

impl PolicyDefinition for TwoFactorAuthenticationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::TwoFactorAuthentication
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::TwoFactorAuthentication
    }
}
