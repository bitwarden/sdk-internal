//! Strongly-typed data layer.

use uuid::Uuid;

use super::{NoData, Policy, PolicyFilter};
use crate::{
    models::{OrganizationUserPolicyContext, PolicyView},
    policy_type::PolicyType,
};

/// How a single organization's policy of a given type applies to the current
/// user.
///
/// Similar to [`PolicyView`], but with two differences:
/// - `enabled` is replaced by `enforced`, which reflects user-specific evaluation rather than just
///   the policy's on/off state.
/// - `data` is strongly typed via the policy's [`PolicyData::Data`].
///
/// When no matching policy is found for the requested organization, `enforced`
/// is `false` and `data` is `None`.
#[derive(Debug, Clone, PartialEq)]
pub struct EnforcedPolicy<D> {
    /// The organization this enforcement decision is for.
    pub organization_id: Uuid,
    /// The policy type.
    pub r#type: PolicyType,
    /// Whether the policy is being enforced against the current user for this
    /// organization.
    pub enforced: bool,
    /// Strongly-typed policy data, if the policy carries any and is enforced.
    pub data: Option<D>,
}

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

/// Extension trait that adds an
/// [`enforced_policy`](PolicyDataFilter::enforced_policy) method to every
/// [`PolicyData`]. Implemented automatically for all `P: PolicyData`.
pub trait PolicyDataFilter: PolicyData {
    /// Returns the [`EnforcedPolicy`] for `organization_id` against the current
    /// user. Performs a targeted lookup — does not iterate the full filter
    /// pipeline. Always returns a non-`None` result; when no matching policy
    /// applies, the returned [`EnforcedPolicy`] has `enforced=false` and
    /// `data=None`.
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
