#![allow(dead_code)]

//! Policy filtering and enforcement logic.
//!
//! The framework is layered:
//! - [`Policy`] defines per-policy filtering rules.
//! - [`PolicyData`] defines how strongly typed data is handled.
//! - [`PolicyAggregate`] is opt-in for policies that can be combined across organizations.
//!
//! Each layer ships an extension trait — [`PolicyFilter`], [`EnforcedPolicyFilter`],
//! [`PolicyAggregateFilter`] — providing the computed enforcement APIs.

mod aggregate;
mod data;
mod policy;

pub use aggregate::{EnforcedAggregatePolicy, PolicyAggregate, PolicyAggregateFilter};
pub use data::{EnforcedPolicy, EnforcedPolicyFilter, NoData, PolicyData};
pub use policy::{Policy, PolicyFilter};

#[cfg(test)]
pub(crate) mod test_helpers {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    use crate::{
        Policy, PolicyAggregate, PolicyData,
        enforcement::data::NoData,
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
    pub struct TestMasterPasswordPolicy;
    impl Policy for TestMasterPasswordPolicy {
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
    impl NoData for TestMasterPasswordPolicy {}

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
