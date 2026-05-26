//! Aggregation layer — combining typed policy data across organizations.

use super::{NoData, Policy, PolicyData, PolicyFilter};
use crate::{
    models::{OrganizationUserPolicyContext, PolicyView},
    policy_type::PolicyType,
};

/// The aggregated enforcement of a single policy type across all of the user's
/// organizations.
///
/// `enforced` is `true` if any of the user's organization policies of this type
/// are enforced. `data` is the combination of the underlying enforced policies'
/// data, computed via [`PolicyAggregate::aggregate`]; how those values are
/// combined is determined by the policy itself.
#[derive(Debug, Clone, PartialEq)]
pub struct EnforcedCombinedPolicy<D> {
    /// The policy type.
    pub r#type: PolicyType,
    /// Whether at least one of the user's organizations is enforcing this
    /// policy.
    pub enforced: bool,
    /// The aggregated strongly-typed policy data, if any enforced policy
    /// carried data.
    pub data: Option<D>,
}

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

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::enforcement::{
        PolicyDataFilter,
        test_helpers::{DemoData, DemoPolicy, demo_policy_view, org},
    };

    #[test]
    fn enforced_policy_returns_typed_data() {
        let org_id = Uuid::new_v4();
        let policies = [demo_policy_view(org_id, Some(r#"{"min":8}"#))];
        let orgs = [org(org_id)];

        let result = DemoPolicy.enforced_policy(org_id, &policies, &orgs);

        assert!(result.enforced);
        assert_eq!(result.data, Some(DemoData { min: 8 }));
        assert_eq!(result.organization_id, org_id);
    }

    #[test]
    fn enforced_combined_policy_aggregates_data() {
        let org1 = Uuid::new_v4();
        let org2 = Uuid::new_v4();
        let policies = [
            demo_policy_view(org1, Some(r#"{"min":8}"#)),
            demo_policy_view(org2, Some(r#"{"min":14}"#)),
        ];
        let orgs = [org(org1), org(org2)];

        let result = DemoPolicy.enforced_combined_policy(&policies, &orgs);

        assert!(result.enforced);
        assert_eq!(result.data, Some(DemoData { min: 14 }));
    }

    #[test]
    fn enforced_combined_policy_returns_not_enforced_when_no_policies() {
        let result = DemoPolicy.enforced_combined_policy(&[], &[]);

        assert!(!result.enforced);
        assert_eq!(result.data, None);
    }
}
