#![allow(dead_code)]

//! Policy filtering and enforcement logic.
//!
//! The framework is layered:
//! - [`Policy`] defines per-policy filtering rules.
//! - [`PolicyData`] is opt-in for policies that carry strongly-typed data.
//! - [`PolicyAggregate`] is opt-in for policies whose data can be combined across organizations.
//!
//! Each layer ships an extension trait — [`PolicyFilter`], [`PolicyDataFilter`],
//! [`PolicyAggregateFilter`] — providing the computed enforcement APIs.

use std::collections::HashMap;

use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use uuid::Uuid;

use crate::{
    models::{OrganizationUserPolicyContext, PolicyView},
    policy_type::PolicyType,
};

mod aggregate;
mod data;

pub use aggregate::{EnforcedAggregatePolicy, PolicyAggregate, PolicyAggregateFilter};
pub use data::{EnforcedPolicy, PolicyData, PolicyDataFilter};

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
/// Implementing this trait gives the policy free [`PolicyData`] and
/// [`PolicyAggregate`] implementations with `Data = ()`, so it can use
/// [`PolicyDataFilter::enforced_policy`] and
/// [`PolicyAggregateFilter::enforced_aggregate_policy`] without declaring any
/// data plumbing.
pub trait NoData {}

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

#[cfg(test)]
pub(crate) mod test_helpers {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    use super::{NoData, Policy, PolicyAggregate, PolicyData};
    use crate::{
        models::{OrganizationUserPolicyContext, PolicyView},
        policy_type::PolicyType,
    };

    pub fn policy_view(
        organization_id: Uuid,
        policy_type: PolicyType,
        enabled: bool,
    ) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: policy_type,
            data: None,
            enabled,
            revision_date: Default::default(),
        }
    }

    pub fn organization(
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

    /// A [`NoData`] policy used by tests that don't care about typed data.
    pub struct TestPolicy;
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

    /// A policy with strongly-typed data, used by tests that exercise the
    /// [`PolicyData`] and [`PolicyAggregate`] layers.
    pub struct DemoPolicy;

    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    pub struct DemoData {
        pub min: i32,
    }

    impl Policy for DemoPolicy {
        fn policy_type(&self) -> PolicyType {
            PolicyType::MasterPassword
        }

        fn exempt_roles(&self) -> &[OrganizationUserType] {
            &[]
        }
    }

    impl PolicyData for DemoPolicy {
        type Data = DemoData;

        fn parse_data(&self, raw: Option<&str>) -> Self::Data {
            raw.and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default()
        }
    }

    impl PolicyAggregate for DemoPolicy {
        fn aggregate(&self, items: Vec<Self::Data>) -> Self::Data {
            DemoData {
                min: items.iter().map(|d| d.min).max().unwrap_or(0),
            }
        }
    }

    pub fn demo_policy_view(organization_id: Uuid, data: Option<&str>) -> PolicyView {
        demo_policy_view_with_enabled(organization_id, data, true)
    }

    pub fn demo_policy_view_with_enabled(
        organization_id: Uuid,
        data: Option<&str>,
        enabled: bool,
    ) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: PolicyType::MasterPassword,
            data: data.map(str::to_string),
            enabled,
            revision_date: Default::default(),
        }
    }

    pub fn org(id: Uuid) -> OrganizationUserPolicyContext {
        OrganizationUserPolicyContext {
            id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: true,
            is_provider_user: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use uuid::Uuid;

    use super::{test_helpers::*, *};

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
}
