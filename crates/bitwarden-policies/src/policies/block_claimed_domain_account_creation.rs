use crate::{PolicyDefinition, PolicyType, policy_type::PolicyDataType};

/// Block Claimed Domain Account Creation policy.
pub struct BlockClaimedDomainAccountCreationPolicy;

impl PolicyDefinition for BlockClaimedDomainAccountCreationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::BlockClaimedDomainAccountCreation
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::BlockClaimedDomainAccountCreation
    }
}
