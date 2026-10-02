use crate::{PolicyDefinition, PolicyType, policy_type::PolicyDataType};

/// Activate Autofill policy.
pub struct ActivateAutofillPolicy;

impl PolicyDefinition for ActivateAutofillPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::ActivateAutofill
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::ActivateAutofill
    }
}
