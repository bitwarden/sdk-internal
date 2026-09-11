use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Require Single Sign-On policy.
pub struct RequireSsoPolicy;

impl Policy for RequireSsoPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::RequireSso
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::RequireSso
    }
}
