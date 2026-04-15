use std::collections::HashMap;

use bitwarden_organizations::{
    OrganizationUserStatusType, OrganizationUserType, ProfileOrganization,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(PartialEq, Serialize, Deserialize, Debug)]
pub struct RawPolicyType(pub i32);

#[derive(Serialize, Deserialize, Debug)]
pub struct RawPolicy {
    id: Uuid,
    organization_id: Uuid,
    r#type: RawPolicyType,
    data: Option<HashMap<String, serde_json::Value>>,
    enabled: bool,
}

pub trait PolicyDefinition: Send + Sync + 'static {
    /// The wire-format integer for this policy type. Known at compile time
    /// and usable in static contexts.
    const TYPE: RawPolicyType;

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

pub fn filter<'a, P: PolicyDefinition>(
    policy_definition: &P,
    policies: &'a [RawPolicy],
    organizations: &[ProfileOrganization],
) -> Vec<&'a RawPolicy> {
    let org_map: HashMap<&Uuid, &ProfileOrganization> =
        organizations.iter().map(|o| (&o.id, o)).collect();

    policies
        .iter()
        .filter(|p| p.r#type == P::TYPE)
        .filter(|p| p.enabled)
        .filter(|p| {
            match org_map.get(&p.organization_id) {
                Some(org) => {
                    org.enabled
                        && org.use_policies
                        && policy_definition
                            .applicable_statuses()
                            .contains(&org.status)
                        && !policy_definition.exempt_roles().contains(&org.r#type)
                        && !(org.is_provider_user && policy_definition.exempt_providers())
                }
                None => true, // Unknown org: enforce by default
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_policy(organization_id: Uuid, policy_type: i32, enabled: bool) -> RawPolicy {
        RawPolicy {
            id: Uuid::new_v4(),
            organization_id,
            r#type: RawPolicyType(policy_type),
            data: None,
            enabled,
        }
    }

    fn organization(
        id: Uuid,
        user_type: OrganizationUserType,
        status: OrganizationUserStatusType,
        provider: bool,
    ) -> ProfileOrganization {
        ProfileOrganization {
            id,
            r#type: user_type,
            status,
            use_policies: true,
            is_provider_user: provider,
            ..Default::default()
        }
    }

    struct TestPolicy;
    impl PolicyDefinition for TestPolicy {
        const TYPE: RawPolicyType = RawPolicyType(1);

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

    #[test]
    fn matching_policy_is_returned() {
        let org_id = Uuid::new_v4();
        let policies = [raw_policy(org_id, 1, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = filter(&TestPolicy, &policies, &orgs);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn disabled_organization_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let orgs = [ProfileOrganization {
            enabled: false,
            id: org_id,
            r#type: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: true,
            is_provider_user: false,
            ..Default::default()
        }];
        let policies = [raw_policy(org_id, 1, true)];

        let result = filter(&TestPolicy, &policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn disabled_policy_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [raw_policy(org_id, 1, false)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = filter(&TestPolicy, &policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn wrong_policy_type_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [raw_policy(org_id, 2, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = filter(&TestPolicy, &policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn use_policies_false_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let orgs = [ProfileOrganization {
            id: org_id,
            r#type: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: false,
            is_provider_user: false,
            ..Default::default()
        }];
        let policies = [raw_policy(org_id, 1, true)];

        let result = filter(&TestPolicy, &policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn exempt_role_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [raw_policy(org_id, 1, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::Owner,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = filter(&TestPolicy, &policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn non_applicable_status_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [raw_policy(org_id, 1, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Revoked,
            false,
        )];

        let result = filter(&TestPolicy, &policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn provider_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [raw_policy(org_id, 1, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            true,
        )];

        let result = filter(&TestPolicy, &policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn missing_org_enforces_by_default() {
        let policies = [raw_policy(Uuid::new_v4(), 1, true)];

        let result = filter(&TestPolicy, &policies, &[]);
        assert_eq!(result.len(), 1);
    }
}
