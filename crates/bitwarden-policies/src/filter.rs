#![allow(dead_code)]

//! Policy filtering and enforcement logic.
//!
//! [`Policy`] defines the per-policy filtering rules. [`PolicyData`] and
//! [`PolicyAggregate`] are opt-in traits for policies that carry strongly-typed
//! data and that can aggregate that data across organizations. The
//! [`PolicyFilter`], [`PolicyDataFilter`], and [`PolicyAggregateFilter`]
//! extension traits provide the computed enforcement APIs.

use std::collections::HashMap;

use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use uuid::Uuid;

use crate::{
    enforced_policy::{EnforcedCombinedPolicy, EnforcedPolicy},
    models::{OrganizationUserPolicyContext, PolicyView},
    policy_type::PolicyType,
};

/// Defines the filtering behavior for a specific policy type.
///
/// Implement this trait to control how a policy is enforced.
pub trait Policy: Send + Sync + 'static {
    /// Returns the policy type this definition handles.
    fn policy_type(&self) -> PolicyType;

    /// Returns the organization roles that are exempt from this policy.
    ///
    /// Defaults to [`Owner`](OrganizationUserType::Owner) and
    /// [`Admin`](OrganizationUserType::Admin).
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[OrganizationUserType::Owner, OrganizationUserType::Admin]
    }

    /// Returns whether provider users are exempt from this policy.
    ///
    /// Defaults to `true`.
    fn exempt_providers(&self) -> bool {
        true
    }

    /// Returns the organization membership statuses for which this policy applies.
    ///
    /// Defaults to [`Accepted`](OrganizationUserStatusType::Accepted) and
    /// [`Confirmed`](OrganizationUserStatusType::Confirmed).
    fn applicable_statuses(&self) -> &[OrganizationUserStatusType] {
        &[
            OrganizationUserStatusType::Accepted,
            OrganizationUserStatusType::Confirmed,
        ]
    }
}

/// Marker trait declaring that a [`Policy`] carries no typed data.
///
/// Implementing this trait gives the policy a free [`PolicyData`] implementation
/// with `Data = ()`, so it can use [`PolicyDataFilter::enforced_policy`] without
/// declaring any data plumbing.
pub trait NoData {}

/// Opt-in extension for policies that carry strongly-typed data.
///
/// Implementing this trait unlocks [`PolicyDataFilter::enforced_policy`] for
/// the policy. Policies with no data can implement [`NoData`] instead and get
/// a trivial [`PolicyData`] implementation for free.
pub trait PolicyData: Policy {
    /// The strongly-typed data this policy carries.
    type Data;

    /// Parses the raw JSON `data` field of a [`PolicyView`] into this policy's
    /// typed [`Data`](Self::Data). Returns `None` when the policy carries no
    /// data or the field is absent or unparseable.
    fn parse_data(&self, raw: Option<&str>) -> Option<Self::Data>;
}

impl<P: Policy + NoData> PolicyData for P {
    type Data = ();

    fn parse_data(&self, _: Option<&str>) -> Option<Self::Data> {
        None
    }
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

/// Extension trait that adds [`enforced`](PolicyFilter::enforced) and
/// [`filter`](PolicyFilter::filter) methods to every [`Policy`]. Implemented
/// automatically for all `T: Policy`.
pub trait PolicyFilter: Policy {
    /// Evaluates whether a single [`PolicyView`] is enforced against the user
    /// based on this policy's rules. If the policy's organization is not
    /// present in `context`, the policy is enforced by default.
    fn enforced(&self, view: &PolicyView, context: Option<&OrganizationUserPolicyContext>) -> bool {
        if view.r#type != self.policy_type() || !view.enabled {
            return false;
        }
        match context {
            Some(org) => {
                org.enabled
                    && org.use_policies
                    && self.applicable_statuses().contains(&org.status)
                    && !self.exempt_roles().contains(&org.role)
                    && !(org.is_provider_user && self.exempt_providers())
            }
            None => true, // Unknown org: enforce by default
        }
    }

    /// Filters `policies` to those that should be enforced against the user.
    /// This evaluates common business rules (e.g. the policy is enabled),
    /// as well as policy-specific rules according to its [`Policy`].
    ///
    /// If a policy's organization is not present in
    /// `organization_user_policy_contexts`, the policy is enforced by default.
    fn filter<'a>(
        &self,
        policies: &'a [PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<&'a PolicyView> {
        let org_map: HashMap<&Uuid, &OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .iter()
                .map(|o| (&o.id, o))
                .collect();

        policies
            .iter()
            .filter(|p| self.enforced(p, org_map.get(&p.organization_id).copied()))
            .collect()
    }
}

impl<T: Policy> PolicyFilter for T {}

/// Extension trait that adds an
/// [`enforced_policy`](PolicyDataFilter::enforced_policy) method to every
/// [`PolicyData`]. Implemented automatically for all `P: PolicyData`.
pub trait PolicyDataFilter: PolicyData {
    /// Returns the [`EnforcedPolicy`] for `organization_id` against the current
    /// user. Performs a targeted lookup — does not iterate the full filter
    /// pipeline. Always returns a non-`None` result; when no matching policy
    /// applies, the returned [`EnforcedPolicy`] has `enforced=false` and the
    /// record-derived fields are `None`.
    fn enforced_policy(
        &self,
        organization_id: Uuid,
        policies: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> EnforcedPolicy<Self::Data>
    where
        Self: Sized,
    {
        // Server invariant: at most one policy per (organization, type).
        let view = policies
            .iter()
            .find(|p| p.organization_id == organization_id && p.r#type == self.policy_type());
        let context = organization_user_policy_contexts
            .iter()
            .find(|c| c.id == organization_id);

        match view {
            Some(v) if self.enforced(v, context) => EnforcedPolicy {
                organization_id,
                r#type: self.policy_type(),
                enforced: true,
                data: self.parse_data(v.data.as_deref()),
            },
            _ => EnforcedPolicy {
                organization_id,
                r#type: self.policy_type(),
                enforced: false,
                data: None,
            },
        }
    }
}

impl<P: PolicyData> PolicyDataFilter for P {}

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
    use super::*;

    fn policy_view(organization_id: Uuid, policy_type: PolicyType, enabled: bool) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: policy_type,
            data: None,
            enabled,
            revision_date: Default::default(),
        }
    }

    fn organization(
        id: Uuid,
        user_type: OrganizationUserType,
        status: OrganizationUserStatusType,
        provider: bool,
    ) -> OrganizationUserPolicyContext {
        OrganizationUserPolicyContext {
            id,
            role: user_type,
            status,
            enabled: true,
            use_policies: true,
            is_provider_user: provider,
        }
    }

    struct TestPolicy;
    impl Policy for TestPolicy {
        fn policy_type(&self) -> PolicyType {
            PolicyType::MasterPassword
        }

        // These happen to match the default impl, but repeating here
        // to decouple the filter tests from the default impl
        fn exempt_roles(&self) -> &[OrganizationUserType] {
            &[OrganizationUserType::Owner, OrganizationUserType::Admin]
        }

        fn exempt_providers(&self) -> bool {
            true
        }

        fn applicable_statuses(&self) -> &[OrganizationUserStatusType] {
            &[
                OrganizationUserStatusType::Accepted,
                OrganizationUserStatusType::Confirmed,
            ]
        }
    }
    impl NoData for TestPolicy {}

    #[test]
    fn matching_policy_is_returned() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn disabled_organization_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let orgs = [OrganizationUserPolicyContext {
            enabled: false,
            id: org_id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: true,
            is_provider_user: false,
        }];
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn disabled_policy_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, false)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn wrong_policy_type_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::PasswordGenerator, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn use_policies_false_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let orgs = [OrganizationUserPolicyContext {
            id: org_id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: false,
            is_provider_user: false,
        }];
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn exempt_role_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::Owner,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn non_applicable_status_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Revoked,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn provider_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            true,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn missing_org_enforces_by_default() {
        let policies = [policy_view(
            Uuid::new_v4(),
            PolicyType::MasterPassword,
            true,
        )];

        let result = TestPolicy.filter(&policies, &[]);
        assert_eq!(result.len(), 1);
    }

    // --- enforced_policy ---

    #[test]
    fn enforced_policy_is_enforced_when_matching() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.enforced_policy(org_id, &policies, &orgs);

        assert!(result.enforced);
        assert_eq!(result.organization_id, org_id);
        assert_eq!(result.r#type, PolicyType::MasterPassword);
    }

    #[test]
    fn enforced_policy_not_enforced_when_no_policy() {
        let org_id = Uuid::new_v4();

        let result = TestPolicy.enforced_policy(org_id, &[], &[]);

        assert!(!result.enforced);
        assert_eq!(result.organization_id, org_id);
        assert_eq!(result.r#type, PolicyType::MasterPassword);
    }

    #[test]
    fn enforced_policy_not_enforced_when_policy_disabled() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, false)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.enforced_policy(org_id, &policies, &orgs);

        assert!(!result.enforced);
    }

    #[test]
    fn enforced_policy_not_enforced_when_user_exempt() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::Owner,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.enforced_policy(org_id, &policies, &orgs);

        assert!(!result.enforced);
    }

    #[test]
    fn enforced_policy_enforced_when_org_context_missing() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = TestPolicy.enforced_policy(org_id, &policies, &[]);

        assert!(result.enforced);
    }
}
