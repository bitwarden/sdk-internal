use bitwarden_organizations::OrganizationUserType;

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Free Families Sponsorship policy.
pub struct FreeFamiliesSponsorshipPolicy;

impl Policy for FreeFamiliesSponsorshipPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::FreeFamiliesSponsorship
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::FreeFamiliesSponsorship
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}
