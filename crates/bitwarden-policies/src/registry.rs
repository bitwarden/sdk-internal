use std::collections::HashMap;

use bitwarden_organizations::{
    OrganizationUserStatusType, OrganizationUserType, ProfileOrganization,
};

use crate::filter::{DefaultPolicyDefinition, Policy, PolicyType, PolicyView, filter};

trait ErasedPolicy {
    fn policy_type(&self) -> PolicyType;
    fn filter_raw<'a>(
        &self,
        policies: &'a [PolicyView],
        organizations: &[ProfileOrganization],
    ) -> Vec<&'a PolicyView>;
}

impl<P: Policy> ErasedPolicy for P {
    fn policy_type(&self) -> PolicyType {
        self.policy_type()
    }

    fn filter_raw<'a>(
        &self,
        policies: &'a [PolicyView],
        organizations: &[ProfileOrganization],
    ) -> Vec<&'a PolicyView> {
        filter(self, policies, organizations)
    }
}

pub struct PolicyRegistry {
    policies: HashMap<PolicyType, Box<dyn ErasedPolicy>>,
}

impl PolicyRegistry {
    pub fn builder() -> PolicyRegistryBuilder {
        PolicyRegistryBuilder {
            policies: HashMap::new(),
        }
    }

    pub(crate) fn filter_by_type<'a>(
        &self,
        policies: &'a [PolicyView],
        organizations: &[ProfileOrganization],
        policy_type: PolicyType,
    ) -> Vec<&'a PolicyView> {
        match self.policies.get(&policy_type) {
            Some(p) => p.filter_raw(policies, organizations),
            None => DefaultPolicyDefinition(policy_type).filter_raw(policies, organizations),
        }
    }
}

pub struct PolicyRegistryBuilder {
    policies: HashMap<PolicyType, Box<dyn ErasedPolicy>>,
}

impl PolicyRegistryBuilder {
    pub fn register<P: Policy>(mut self, policy: P) -> Self {
        self.policies.insert(policy.policy_type(), Box::new(policy));
        self
    }

    pub fn build(self) -> PolicyRegistry {
        PolicyRegistry {
            policies: self.policies,
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn policy_view(organization_id: Uuid, policy_type: u8, enabled: bool) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: PolicyType(policy_type),
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

    #[test]
    fn registry_uses_registered_definition() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 1, true)];
        // Owner — exempt under default rules, not exempt under NoExemptionPolicy
        let orgs = [organization(
            org_id,
            OrganizationUserType::Owner,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        struct NoExemptionPolicy;
        impl Policy for NoExemptionPolicy {
            fn policy_type(&self) -> PolicyType {
                PolicyType(1)
            }
            fn exempt_roles(&self) -> &[OrganizationUserType] {
                &[]
            }
        }

        let registry = PolicyRegistry::builder()
            .register(NoExemptionPolicy)
            .build();

        let result = registry.filter_by_type(&policies, &orgs, PolicyType(1));

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn registry_uses_default_policy_definition() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 1, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        // empty registry
        let registry = PolicyRegistry::builder().build();

        let result = registry.filter_by_type(&policies, &orgs, PolicyType(1));

        assert_eq!(result.len(), 1);
    }
}
