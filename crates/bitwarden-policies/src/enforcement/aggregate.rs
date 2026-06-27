//! Aggregation layer — combining typed policy data across organizations.

use super::{Policy, PolicyData, PolicyFilter, data::NoData};
use crate::{
    enforcement::EnforcedPolicyFilter,
    models::{OrganizationUserPolicyContext, PolicyView},
    policy_type::PolicyType,
};

/// The aggregated enforcement of a single policy type across all of the user's
/// organizations.
///
/// `enforced` is `true` if any of the user's organization policies of this type
/// are enforced. `data` is the combination of the underlying enforced policies'
/// data, computed via [`PolicyAggregate::aggregate`]; how those values are
/// combined is determined by the policy itself. When no policy is enforced,
/// `data` is [`Default::default()`].
#[derive(Debug, Clone, PartialEq)]
pub struct EnforcedAggregatePolicy<D> {
    /// The policy type.
    pub r#type: PolicyType,
    /// Whether at least one of the user's organizations is enforcing this
    /// policy.
    pub enforced: bool,
    /// The aggregated strongly-typed policy data, or [`Default::default()`]
    /// when not enforced.
    pub data: D,
}

/// Opt-in extension for policies whose data can be combined across
/// organizations.
///
/// Implementing this trait unlocks
/// [`PolicyAggregateFilter::get_enforced_aggregate_policy`] for the policy.
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

/// Extension trait that adds a
/// [`get_enforced_aggregate_policy`](PolicyAggregateFilter::get_enforced_aggregate_policy)
/// method to every [`PolicyAggregate`]. Implemented automatically for all
/// `P: PolicyAggregate`.
pub trait PolicyAggregateFilter: PolicyAggregate {
    /// Returns the [`EnforcedAggregatePolicy`] aggregating this policy type
    /// across all of the user's organizations. `enforced` is `true` if any of
    /// the user's organizations enforce this policy. `data` is the
    /// [`aggregate`](PolicyAggregate::aggregate) of the underlying enforced
    /// policies' data (combined as determined by the policy), or
    /// [`Default::default()`] when no policy is enforced.
    fn get_enforced_aggregate_policy(
        &self,
        policies: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> EnforcedAggregatePolicy<Self::Data>
    where
        Self: Sized,
    {
        let filtered = self.filter(policies, organization_user_policy_contexts);
        let data = if filtered.is_empty() {
            Self::Data::default()
        } else {
            let data_items: Vec<Self::Data> = filtered
                .iter()
                .map(|p| self.get_data_or_default(p))
                .collect();
            self.aggregate(data_items)
        };
        EnforcedAggregatePolicy {
            r#type: self.policy_type(),
            enforced: !filtered.is_empty(),
            data,
        }
    }
}

impl<P: PolicyAggregate> PolicyAggregateFilter for P {}

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use uuid::Uuid;

    use super::*;
    use crate::enforcement::{EnforcedPolicyFilter, test_helpers::*};

    #[test]
    fn enforced_policy_returns_typed_data() {
        let org_id = Uuid::new_v4();
        let policies = [demo_policy_view(org_id, Some(r#"{"min":8}"#))];
        let orgs = [org(org_id)];

        let result = DemoPolicy.get_enforced_policy(org_id, &policies, &orgs);

        assert!(result.enforced);
        assert_eq!(result.data, DemoData { min: 8 });
        assert_eq!(result.organization_id, org_id);
    }

    #[test]
    fn enforced_aggregate_policy_aggregates_data() {
        let org1 = Uuid::new_v4();
        let org2 = Uuid::new_v4();
        let policies = [
            demo_policy_view(org1, Some(r#"{"min":8}"#)),
            demo_policy_view(org2, Some(r#"{"min":14}"#)),
        ];
        let orgs = [org(org1), org(org2)];

        let result = DemoPolicy.get_enforced_aggregate_policy(&policies, &orgs);

        assert!(result.enforced);
        assert_eq!(result.data, DemoData { min: 14 });
    }

    #[test]
    fn enforced_aggregate_policy_returns_not_enforced_when_no_policies() {
        let result = DemoPolicy.get_enforced_aggregate_policy(&[], &[]);

        assert!(!result.enforced);
        assert_eq!(result.data, DemoData::default());
    }

    #[test]
    fn enforced_aggregate_policy_not_enforced_when_all_orgs_exempt() {
        let org1 = Uuid::new_v4();
        let org2 = Uuid::new_v4();
        let policies = [
            policy_view(org1, PolicyType::MasterPassword, true),
            policy_view(org2, PolicyType::MasterPassword, true),
        ];
        let orgs = [
            organization(
                org1,
                OrganizationUserType::Owner,
                OrganizationUserStatusType::Confirmed,
                false,
            ),
            organization(
                org2,
                OrganizationUserType::Owner,
                OrganizationUserStatusType::Confirmed,
                false,
            ),
        ];

        let result = TestMasterPasswordPolicy.get_enforced_aggregate_policy(&policies, &orgs);

        assert!(!result.enforced);
    }

    #[test]
    fn enforced_aggregate_policy_aggregates_only_enforced_orgs() {
        let org1 = Uuid::new_v4();
        let org2 = Uuid::new_v4();
        let policies = [
            demo_policy_view(org1, Some(r#"{"min":8}"#)),
            // Disabled — should be skipped by the filter, so its `min: 14` does not feed
            // aggregation.
            demo_policy_view_with_enabled(org2, Some(r#"{"min":14}"#), false),
        ];
        let orgs = [org(org1), org(org2)];

        let result = DemoPolicy.get_enforced_aggregate_policy(&policies, &orgs);

        assert!(result.enforced);
        assert_eq!(result.data, DemoData { min: 8 });
    }

    #[test]
    fn enforced_aggregate_policy_data_is_default_when_no_parseable_data() {
        let org1 = Uuid::new_v4();
        let org2 = Uuid::new_v4();
        let policies = [
            demo_policy_view(org1, None),
            demo_policy_view(org2, Some("not json")),
        ];
        let orgs = [org(org1), org(org2)];

        let result = DemoPolicy.get_enforced_aggregate_policy(&policies, &orgs);

        assert!(result.enforced);
        // Both policies parse to Default, aggregation of two defaults stays Default.
        assert_eq!(result.data, DemoData::default());
    }

    #[test]
    fn enforced_aggregate_policy_treats_unparseable_as_default() {
        let org1 = Uuid::new_v4();
        let org2 = Uuid::new_v4();
        let policies = [
            demo_policy_view(org1, Some(r#"{"min":8}"#)),
            demo_policy_view(org2, Some("not json")),
        ];
        let orgs = [org(org1), org(org2)];

        let result = DemoPolicy.get_enforced_aggregate_policy(&policies, &orgs);

        // Unparseable becomes DemoData::default() (min=0); aggregation `max` selects min=8.
        assert!(result.enforced);
        assert_eq!(result.data, DemoData { min: 8 });
    }

    #[test]
    fn enforced_aggregate_policy_nodata_returns_enforced_with_default_data() {
        let org1 = Uuid::new_v4();
        let org2 = Uuid::new_v4();
        let policies = [
            policy_view(org1, PolicyType::MasterPassword, true),
            policy_view(org2, PolicyType::MasterPassword, true),
        ];
        let orgs = [
            organization(
                org1,
                OrganizationUserType::User,
                OrganizationUserStatusType::Confirmed,
                false,
            ),
            organization(
                org2,
                OrganizationUserType::User,
                OrganizationUserStatusType::Confirmed,
                false,
            ),
        ];

        let result = TestMasterPasswordPolicy.get_enforced_aggregate_policy(&policies, &orgs);

        assert!(result.enforced);
        // Data type for a NoData policy is `()` — the assertion is trivial but documents intent.
        assert_eq!(result.data, ());
    }
}
