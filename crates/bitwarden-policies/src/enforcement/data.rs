//! Strongly-typed data layer.

use serde::de::DeserializeOwned;
use uuid::Uuid;

use super::{Policy, PolicyFilter};
use crate::{
    PolicyType,
    models::{OrganizationUserPolicyContext, PolicyView},
};

/// How a specific organization's policy of a given type applies to the current
/// user.
///
/// Similar to [`PolicyView`], but with two differences:
/// - `enabled` is replaced by `enforced`, which reflects user-specific evaluation rather than the
///   policy's raw state.
/// - `data` is strongly typed via the policy's [`PolicyData::Data`].
///
/// `data` is always populated. When no matching policy is found, or when the
/// policy record's data could not be parsed, `data` is [`Default::default()`].
#[derive(Debug, Clone, PartialEq)]
pub struct EnforcedPolicy<D> {
    /// The organization this enforcement decision is for.
    pub organization_id: Uuid,
    /// The policy type.
    pub r#type: PolicyType,
    /// Whether the policy is being enforced against the current user for this
    /// organization.
    pub enforced: bool,
    /// Strongly-typed policy data. [`Default::default()`] when not enforced or
    /// when the policy record's data could not be parsed.
    pub data: D,
}

/// Implement to specify the strongly typed data stored on the [`PolicyView`].
/// If your policy does not carry data, implement [`NoData`] instead.
pub trait PolicyData: Policy {
    /// The strongly-typed data for this policy. The [`Default`] value is
    /// the fall-back whenever the policy is not enforced or the raw data could
    /// not be parsed.
    type Data: Default + DeserializeOwned;
}

/// Marker trait declaring that a [`Policy`] carries no typed data.
///
/// Implementing this trait gives the policy free [`PolicyData`] and
/// [`PolicyAggregate`](super::PolicyAggregate) implementations with
/// `Data = ()`, so it can use [`EnforcedPolicyFilter::get_enforced_policy`] and
/// [`PolicyAggregateFilter::get_enforced_aggregate_policy`](super::PolicyAggregateFilter::get_enforced_aggregate_policy)
/// without declaring any data plumbing.
pub trait NoData {}

impl<P: Policy + NoData> PolicyData for P {
    type Data = ();
}

/// Extension trait that adds a
/// [`get_enforced_policy`](EnforcedPolicyFilter::get_enforced_policy) method to
/// every [`PolicyData`]. Implemented automatically for all `P: PolicyData`.
pub trait EnforcedPolicyFilter: PolicyData {
    /// Deserializes the [`PolicyView::data`] string into the
    /// [`PolicyData::Data`] type. Returns [`Default::default()`] if there is no
    /// data or it cannot be parsed.
    fn get_data_or_default(&self, view: &PolicyView) -> Self::Data {
        match &view.data {
            Some(data) => serde_json::from_str(data).unwrap_or_default(),
            None => Self::Data::default(),
        }
    }

    /// Returns the [`EnforcedPolicy`] for `organization_id` against the current
    /// user. When no matching policy applies, the returned
    /// [`EnforcedPolicy`] has `enforced=false` and `data=Default::default()`.
    fn get_enforced_policy(
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
                data: self.get_data_or_default(v),
            },
            _ => EnforcedPolicy {
                organization_id,
                r#type: self.policy_type(),
                enforced: false,
                data: Self::Data::default(),
            },
        }
    }
}

impl<P: PolicyData> EnforcedPolicyFilter for P {}

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use uuid::Uuid;

    use super::*;
    use crate::enforcement::test_helpers::*;

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

        let result = TestMasterPasswordPolicy.get_enforced_policy(org_id, &policies, &orgs);

        assert!(result.enforced);
        assert_eq!(result.organization_id, org_id);
        assert_eq!(result.r#type, PolicyType::MasterPassword);
    }

    #[test]
    fn enforced_policy_not_enforced_when_no_policy() {
        let org_id = Uuid::new_v4();

        let result = TestMasterPasswordPolicy.get_enforced_policy(org_id, &[], &[]);

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

        let result = TestMasterPasswordPolicy.get_enforced_policy(org_id, &policies, &orgs);

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

        let result = TestMasterPasswordPolicy.get_enforced_policy(org_id, &policies, &orgs);

        assert!(!result.enforced);
    }

    #[test]
    fn enforced_policy_enforced_when_org_context_missing() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = TestMasterPasswordPolicy.get_enforced_policy(org_id, &policies, &[]);

        assert!(result.enforced);
    }

    // --- typed data parsing ---

    #[test]
    fn enforced_policy_data_is_default_when_view_data_absent() {
        let org_id = Uuid::new_v4();
        let policies = [demo_policy_view(org_id, None)];
        let orgs = [org(org_id)];

        let result = DemoPolicy.get_enforced_policy(org_id, &policies, &orgs);

        assert!(result.enforced);
        assert_eq!(result.data, DemoData::default());
    }

    #[test]
    fn enforced_policy_data_is_default_when_view_data_unparseable() {
        let org_id = Uuid::new_v4();
        let policies = [demo_policy_view(org_id, Some("not json"))];
        let orgs = [org(org_id)];

        let result = DemoPolicy.get_enforced_policy(org_id, &policies, &orgs);

        assert!(result.enforced);
        assert_eq!(result.data, DemoData::default());
    }

    #[test]
    fn enforced_policy_data_is_default_when_not_enforced() {
        let org_id = Uuid::new_v4();

        let result = DemoPolicy.get_enforced_policy(org_id, &[], &[]);

        assert!(!result.enforced);
        assert_eq!(result.data, DemoData::default());
    }
}
