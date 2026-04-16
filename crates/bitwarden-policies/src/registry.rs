#![allow(dead_code)]

//! Policy registry for managing [`Policy`] implementations.
//!
//! The [`PolicyRegistry`] maps policy types to their definitions
//! and provides an interface for filtering policies according to their registered definition.
//! Unregistered policy types fall back to [`DefaultPolicy`].

use std::collections::HashMap;

use bitwarden_organizations::ProfileOrganization;

use crate::filter::{Policy, PolicyFilter, PolicyType, PolicyView};

/// A [`Policy`] that uses the default filtering behavior for any policy type.
struct DefaultPolicy(PolicyType);

impl Policy for DefaultPolicy {
    fn policy_type(&self) -> PolicyType {
        self.0
    }
}

/// A registry mapping each [`PolicyType`] to its [`Policy`] implementation.
///
/// This is for FFI callers where the [`Policy`] implementation is unknown.
/// Rust callers should call [`filter`](PolicyFilter::filter)
/// directly on their desired [`Policy`].
///
/// Use [`PolicyRegistry::builder`] to construct an instance.
pub struct PolicyRegistry {
    policies: HashMap<PolicyType, Box<dyn PolicyFilter>>,
}

impl PolicyRegistry {
    /// Returns a [`PolicyRegistryBuilder`] for constructing a registry.
    pub fn builder() -> PolicyRegistryBuilder {
        PolicyRegistryBuilder {
            policies: HashMap::new(),
        }
    }

    /// Filters `policies` to those of `policy_type` that should be enforced.
    ///
    /// Uses the registered [`Policy`] for `policy_type` if one exists,
    /// otherwise falls back to [`DefaultPolicy`].
    pub(crate) fn filter_by_type<'a>(
        &self,
        policies: &'a [PolicyView],
        organizations: &[ProfileOrganization],
        policy_type: PolicyType,
    ) -> Vec<&'a PolicyView> {
        match self.policies.get(&policy_type) {
            Some(p) => p.filter(policies, organizations),
            None => DefaultPolicy(policy_type).filter(policies, organizations),
        }
    }
}

/// Builder for [`PolicyRegistry`].
pub struct PolicyRegistryBuilder {
    policies: HashMap<PolicyType, Box<dyn PolicyFilter>>,
}

impl PolicyRegistryBuilder {
    /// Registers a [`Policy`] for its policy type.
    ///
    /// If a definition for the same type is already registered, it is replaced.
    pub fn register<P: Policy>(mut self, policy: P) -> Self {
        self.policies.insert(policy.policy_type(), Box::new(policy));
        self
    }

    /// Builds the [`PolicyRegistry`].
    pub fn build(self) -> PolicyRegistry {
        PolicyRegistry {
            policies: self.policies,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
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
