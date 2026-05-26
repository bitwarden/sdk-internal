//! User-centric views of policy enforcement.
//!
//! [`EnforcedPolicy`] and [`EnforcedCombinedPolicy`] represent how a policy
//! applies to the current user, rather than the raw server record.

use uuid::Uuid;

use crate::policy_type::PolicyType;

/// How a single organization's policy of a given type applies to the current user.
///
/// Similar to [`PolicyView`](crate::PolicyView), but with two differences:
/// - `enabled` is replaced by `enforced`, which reflects user-specific evaluation rather than just
///   the policy's on/off state.
/// - `data` is strongly typed via the policy's
///   [`PolicyData::Data`](crate::filter::PolicyData::Data).
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

/// The aggregated enforcement of a single policy type across all of the user's
/// organizations.
///
/// `enforced` is `true` if any of the user's organization policies of this type
/// are enforced. `data` is the combination of the underlying enforced policies'
/// data, computed via
/// [`PolicyAggregate::aggregate`](crate::filter::PolicyAggregate::aggregate).
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

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    use crate::{
        OrganizationUserPolicyContext, PolicyView,
        filter::{Policy, PolicyAggregate, PolicyAggregateFilter, PolicyData, PolicyDataFilter},
        policy_type::PolicyType,
    };

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct DemoData {
        min: i32,
    }

    struct DemoPolicy;

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

        fn parse_data(&self, raw: Option<&str>) -> Option<Self::Data> {
            raw.and_then(|s| serde_json::from_str(s).ok())
        }
    }

    impl PolicyAggregate for DemoPolicy {
        fn aggregate(&self, items: Vec<Self::Data>) -> Self::Data {
            DemoData {
                min: items.iter().map(|d| d.min).max().unwrap_or(0),
            }
        }
    }

    fn policy_view(organization_id: Uuid, data: Option<&str>) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: PolicyType::MasterPassword,
            data: data.map(str::to_string),
            enabled: true,
            revision_date: Default::default(),
        }
    }

    fn org(id: Uuid) -> OrganizationUserPolicyContext {
        OrganizationUserPolicyContext {
            id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: true,
            is_provider_user: false,
        }
    }

    #[test]
    fn enforced_policy_returns_typed_data() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, Some(r#"{"min":8}"#))];
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
            policy_view(org1, Some(r#"{"min":8}"#)),
            policy_view(org2, Some(r#"{"min":14}"#)),
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
