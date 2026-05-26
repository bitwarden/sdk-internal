//! Aggregation layer — combining typed policy data across organizations.

use super::{NoData, Policy, PolicyData, PolicyFilter};
use crate::{
    enforced_policy::EnforcedCombinedPolicy,
    models::{OrganizationUserPolicyContext, PolicyView},
};

/// Opt-in extension for policies whose data can be combined across
/// organizations.
///
/// Implementing this trait unlocks
/// [`PolicyAggregateFilter::enforced_combined_policy`] for the policy.
/// [`NoData`] policies get a trivial implementation for free.
pub trait PolicyAggregate: PolicyData {
    /// Combines multiple [`Data`](PolicyData::Data) values into a single value.
    /// How those values are combined is determined by the policy. Will only be
    /// called with a non-empty `items`.
    fn aggregate(&self, items: Vec<Self::Data>) -> Self::Data;
}

impl<P: Policy + NoData> PolicyAggregate for P {
    fn aggregate(&self, _: Vec<Self::Data>) -> Self::Data {}
}

/// Extension trait that adds an
/// [`enforced_combined_policy`](PolicyAggregateFilter::enforced_combined_policy)
/// method to every [`PolicyAggregate`]. Implemented automatically for all
/// `P: PolicyAggregate`.
pub trait PolicyAggregateFilter: PolicyAggregate {
    /// Returns the [`EnforcedCombinedPolicy`] aggregating this policy type
    /// across all of the user's organizations. `enforced` is `true` if any of
    /// the user's organizations enforce this policy. `data` is the
    /// [`aggregate`](PolicyAggregate::aggregate) of the underlying enforced
    /// policies' data (combined as determined by the policy), or `None` if no
    /// policy carried parseable data.
    fn enforced_combined_policy(
        &self,
        policies: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> EnforcedCombinedPolicy<Self::Data>
    where
        Self: Sized,
    {
        let filtered = self.filter(policies, organization_user_policy_contexts);
        let enforced = !filtered.is_empty();
        let data_items: Vec<Self::Data> = filtered
            .iter()
            .filter_map(|p| self.parse_data(p.data.as_deref()))
            .collect();
        let data = if data_items.is_empty() {
            None
        } else {
            Some(self.aggregate(data_items))
        };
        EnforcedCombinedPolicy {
            r#type: self.policy_type(),
            enforced,
            data,
        }
    }
}

impl<P: PolicyAggregate> PolicyAggregateFilter for P {}
