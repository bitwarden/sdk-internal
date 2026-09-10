use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Block Claimed Domain Account Creation policy.
pub struct BlockClaimedDomainAccountCreationPolicy;

impl Policy for BlockClaimedDomainAccountCreationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::BlockClaimedDomainAccountCreation
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::BlockClaimedDomainAccountCreation
    }
}
