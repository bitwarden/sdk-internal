//! [`PolicyClient`] and its associated extension trait.

use std::collections::HashMap;

use bitwarden_core::{Client, OrganizationId};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{OrganizationUserPolicyContext, PolicyType, PolicyView, models::EnforcedPolicyErased};
// The strongly-typed native enforcement API is test-only for now: it is exercised by tests but
// not yet exposed to consumers. See the `#[cfg(test)]` impl block below.
#[cfg(test)]
use crate::{Policy, models::EnforcedPolicy, policy::EnforceablePolicy};

/// Client for policy domain operations.
///
/// Obtained via [`PoliciesClientExt::policies`] on a [`Client`].
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PolicyClient;

impl Default for PolicyClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyClient {
    /// Creates a new [`PolicyClient`].
    pub fn new() -> Self {
        Self
    }
}

/// FFI client using type erasure to cross the boundary.
/// Native rust callers should use the non-erased interfaces instead.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl PolicyClient {
    /// Evaluate enforcement of the given policy type across all organizations,
    /// returning type-erased decisions for the FFI boundary.
    ///
    /// Not yet intended for consumer use: exposed across the FFI boundary for
    /// testing and iteration only. Use [`filter_by_type`](Self::filter_by_type) for now.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "get_all_enforced"))]
    pub fn get_all_enforced_erased(
        &self,
        policy_type: PolicyType,
        // TODO: policy_views and ctx should come from state rather than being specified by the
        // caller
        policy_views: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
    ) -> Vec<EnforcedPolicyErased> {
        policy_type
            .resolve_policy()
            .get_all_enforced_erased(&policy_views, &organization_user_policy_contexts)
    }

    /// Evaluate enforcement of the given policy type for a single organization,
    /// returning a type-erased decision for the FFI boundary.
    ///
    /// Not yet intended for consumer use: exposed across the FFI boundary for
    /// testing only. Use [`filter_by_type`](Self::filter_by_type) for now.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "get_enforced"))]
    pub fn get_enforced_erased(
        &self,
        policy_type: PolicyType,
        organization_id: OrganizationId,
        // TODO: policy_views and ctx should come from state rather than being specified by the
        // caller
        policy_views: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
    ) -> EnforcedPolicyErased {
        policy_type.resolve_policy().get_enforced_erased(
            organization_id,
            &policy_views,
            &organization_user_policy_contexts,
        )
    }

    /// Filter policies of the given type for the current user.
    pub fn filter_by_type(
        &self,
        policies: Vec<PolicyView>,
        organization_user_policy_contexts: Vec<OrganizationUserPolicyContext>,
        policy_type: PolicyType,
    ) -> Vec<PolicyView> {
        // Use the enforced path as the canonical logic, then use it to filter the PolicyViews for
        // return
        let enforced: HashMap<OrganizationId, EnforcedPolicyErased> = policy_type
            .resolve_policy()
            .get_all_enforced_erased(&policies, &organization_user_policy_contexts)
            .into_iter()
            .map(|e| (e.organization_id, e))
            .collect();

        policies
            .into_iter()
            .filter(|p| {
                p.r#type == policy_type
                    && match enforced.get(&p.organization_id) {
                        Some(e) => e.enforced,
                        None => false,
                    }
            })
            .collect()
    }
}

/// Native rust client.
///
/// Test-only for now: the strongly-typed enforcement API is not yet exposed to consumers.
#[cfg(test)]
impl PolicyClient {
    /// Evaluate enforcement of the given policy across all organizations,
    /// returning strongly-typed enforcement results.
    fn get_all_enforced<P: Policy>(
        &self,
        policy: P,
        // TODO: policy_views and ctx should come from state rather than being specified by the
        // caller
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<EnforcedPolicy<P>> {
        policy.get_all_enforced(policy_views, organization_user_policy_contexts)
    }

    /// Evaluate enforcement of the given policy for a single organization,
    /// returning a strongly-typed enforcement result.
    fn get_enforced<P: Policy>(
        &self,
        policy: P,
        organization_id: OrganizationId,
        // TODO: policy_views and ctx should come from state rather than being specified by the
        // caller
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> EnforcedPolicy<P> {
        policy.get_enforced(
            organization_id,
            policy_views,
            organization_user_policy_contexts,
        )
    }
}

/// Extension trait that adds a [`policies`](PoliciesClientExt::policies) method to [`Client`].
pub trait PoliciesClientExt {
    /// Creates a new [PolicyClient] instance.
    fn policies(&self) -> PolicyClient;
}

impl PoliciesClientExt for Client {
    fn policies(&self) -> PolicyClient {
        PolicyClient::new()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use uuid::Uuid;

    use super::*;
    use crate::{MasterPasswordPolicy, MasterPasswordPolicyData, policy_type::PolicyDataType};

    fn policy_view(
        organization_id: OrganizationId,
        policy_type: PolicyType,
        data: Option<&str>,
    ) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: policy_type,
            data: data.map(str::to_owned),
            enabled: true,
            revision_date: None,
        }
    }

    /// A confirmed, non-provider member of `organization_id` that a policy applies to.
    fn confirmed_member(organization_id: OrganizationId) -> OrganizationUserPolicyContext {
        OrganizationUserPolicyContext {
            id: organization_id,
            status: OrganizationUserStatusType::Confirmed,
            role: OrganizationUserType::User,
            enabled: true,
            use_policies: true,
            is_provider_user: false,
        }
    }

    mod get_enforced {
        use super::*;

        #[test]
        fn returns_typed_decision() {
            let org_id = OrganizationId::new_v4();
            let views = [policy_view(
                org_id,
                PolicyType::MasterPassword,
                Some(r#"{"minComplexity":3,"minLength":12}"#),
            )];
            let contexts = [confirmed_member(org_id)];

            let result =
                PolicyClient::new().get_enforced(MasterPasswordPolicy, org_id, &views, &contexts);

            assert_eq!(result.organization_id, org_id);
            assert!(result.enforced);
            assert_eq!(
                result.data,
                MasterPasswordPolicyData {
                    min_complexity: Some(3),
                    min_length: Some(12),
                    ..Default::default()
                }
            );
        }
    }

    mod get_all_enforced {
        use super::*;

        #[test]
        fn returns_one_decision_per_view() {
            let org_id = OrganizationId::new_v4();
            let views = [policy_view(
                org_id,
                PolicyType::MasterPassword,
                Some(r#"{"minComplexity":3}"#),
            )];
            let contexts = [confirmed_member(org_id)];

            let results =
                PolicyClient::new().get_all_enforced(MasterPasswordPolicy, &views, &contexts);

            assert_eq!(results.len(), 1);
            assert_eq!(results[0].organization_id, org_id);
            assert!(results[0].enforced);
            assert_eq!(results[0].data.min_complexity, Some(3));
        }
    }

    mod get_enforced_erased {
        use super::*;

        #[test]
        fn returns_erased_decision() {
            let org_id = OrganizationId::new_v4();
            let views = vec![policy_view(
                org_id,
                PolicyType::MasterPassword,
                Some(r#"{"minComplexity":3}"#),
            )];
            let contexts = vec![confirmed_member(org_id)];

            let result = PolicyClient::new().get_enforced_erased(
                PolicyType::MasterPassword,
                org_id,
                views,
                contexts,
            );

            assert_eq!(result.organization_id, org_id);
            assert!(result.enforced);
            assert_eq!(
                result.data,
                PolicyDataType::MasterPassword(MasterPasswordPolicyData {
                    min_complexity: Some(3),
                    ..Default::default()
                })
            );
        }

        #[test]
        fn unit_variant_carries_no_data() {
            let org_id = OrganizationId::new_v4();
            let views = vec![policy_view(org_id, PolicyType::SingleOrg, None)];
            let contexts = vec![confirmed_member(org_id)];

            let result = PolicyClient::new().get_enforced_erased(
                PolicyType::SingleOrg,
                org_id,
                views,
                contexts,
            );

            assert!(result.enforced);
            assert_eq!(result.data, PolicyDataType::SingleOrg);
        }

        #[test]
        fn defaults_when_no_matching_view() {
            let org_id = OrganizationId::new_v4();

            // No view for this org/type: the decision defaults to not-enforced with the
            // default erased data variant.
            let result = PolicyClient::new().get_enforced_erased(
                PolicyType::MasterPassword,
                org_id,
                vec![],
                vec![],
            );

            assert_eq!(result.organization_id, org_id);
            assert!(!result.enforced);
            assert_eq!(
                result.data,
                PolicyDataType::MasterPassword(MasterPasswordPolicyData::default())
            );
        }
    }

    mod get_all_enforced_erased {
        use super::*;

        #[test]
        fn returns_one_decision_per_view() {
            let org_id = OrganizationId::new_v4();
            let views = vec![policy_view(org_id, PolicyType::MasterPassword, None)];
            let contexts = vec![confirmed_member(org_id)];

            let results = PolicyClient::new().get_all_enforced_erased(
                PolicyType::MasterPassword,
                views,
                contexts,
            );

            assert_eq!(results.len(), 1);
            assert_eq!(results[0].organization_id, org_id);
            assert!(results[0].enforced);
            assert_eq!(
                results[0].data,
                PolicyDataType::MasterPassword(MasterPasswordPolicyData::default())
            );
        }

        #[test]
        fn evaluates_each_org_independently() {
            let org_a = OrganizationId::new_v4();
            let org_b = OrganizationId::new_v4();
            let views = vec![
                policy_view(org_a, PolicyType::MaximumVaultTimeout, None),
                policy_view(org_b, PolicyType::MaximumVaultTimeout, None),
            ];
            // org_a's member is a subject User; org_b's member is an Owner, who is exempt
            // from MaximumVaultTimeout.
            let contexts = vec![
                confirmed_member(org_a),
                OrganizationUserPolicyContext {
                    id: org_b,
                    status: OrganizationUserStatusType::Confirmed,
                    role: OrganizationUserType::Owner,
                    enabled: true,
                    use_policies: true,
                    is_provider_user: false,
                },
            ];

            let results = PolicyClient::new().get_all_enforced_erased(
                PolicyType::MaximumVaultTimeout,
                views,
                contexts,
            );

            assert_eq!(results.len(), 2);
            let a = results
                .iter()
                .find(|r| r.organization_id == org_a)
                .expect("a decision for org_a");
            let b = results
                .iter()
                .find(|r| r.organization_id == org_b)
                .expect("a decision for org_b");
            assert!(a.enforced);
            assert!(!b.enforced);
        }
    }

    // Exercised through the public `filter_by_type` (the stable contract), with the real registered
    // policies, so this characterization survives the implementation refactors that follow.
    mod filter_by_type {
        use super::*;

        /// Convenience wrapper around the method under test.
        fn filter(
            policies: Vec<PolicyView>,
            orgs: Vec<OrganizationUserPolicyContext>,
            policy_type: PolicyType,
        ) -> Vec<PolicyView> {
            PolicyClient::new().filter_by_type(policies, orgs, policy_type)
        }

        /// A disabled `PolicyView` for the gate that drops disabled policies.
        fn disabled_policy_view(
            organization_id: OrganizationId,
            policy_type: PolicyType,
        ) -> PolicyView {
            PolicyView {
                enabled: false,
                ..policy_view(organization_id, policy_type, None)
            }
        }

        #[test]
        fn keeps_a_matching_enabled_policy_and_filters_to_the_requested_type() {
            let org_id = OrganizationId::new_v4();
            let policies = vec![
                policy_view(org_id, PolicyType::MasterPassword, None),
                policy_view(org_id, PolicyType::PasswordGenerator, None),
            ];

            let result = filter(
                policies,
                vec![confirmed_member(org_id)],
                PolicyType::MasterPassword,
            );

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].r#type, PolicyType::MasterPassword);
        }

        #[test]
        fn returns_empty_when_no_policy_of_the_requested_type_exists() {
            let org_id = OrganizationId::new_v4();
            let policies = vec![policy_view(org_id, PolicyType::MasterPassword, None)];

            let result = filter(
                policies,
                vec![confirmed_member(org_id)],
                PolicyType::TwoFactorAuthentication,
            );

            assert!(result.is_empty());
        }

        #[test]
        fn drops_a_disabled_policy() {
            let org_id = OrganizationId::new_v4();
            let policies = vec![disabled_policy_view(org_id, PolicyType::MasterPassword)];

            let result = filter(
                policies,
                vec![confirmed_member(org_id)],
                PolicyType::MasterPassword,
            );

            assert!(result.is_empty());
        }

        #[test]
        fn drops_the_policy_when_the_organization_is_disabled() {
            let org_id = OrganizationId::new_v4();
            let policies = vec![policy_view(org_id, PolicyType::MasterPassword, None)];
            let orgs = vec![OrganizationUserPolicyContext {
                enabled: false,
                ..confirmed_member(org_id)
            }];

            let result = filter(policies, orgs, PolicyType::MasterPassword);

            assert!(result.is_empty());
        }

        #[test]
        fn drops_the_policy_when_the_organization_does_not_support_policies() {
            let org_id = OrganizationId::new_v4();
            let policies = vec![policy_view(org_id, PolicyType::MasterPassword, None)];
            let orgs = vec![OrganizationUserPolicyContext {
                use_policies: false,
                ..confirmed_member(org_id)
            }];

            let result = filter(policies, orgs, PolicyType::MasterPassword);

            assert!(result.is_empty());
        }

        #[test]
        fn drops_the_policy_for_a_provider_user() {
            let org_id = OrganizationId::new_v4();
            let policies = vec![policy_view(org_id, PolicyType::MasterPassword, None)];
            let orgs = vec![OrganizationUserPolicyContext {
                is_provider_user: true,
                ..confirmed_member(org_id)
            }];

            let result = filter(policies, orgs, PolicyType::MasterPassword);

            assert!(result.is_empty());
        }

        #[test]
        fn drops_the_policy_for_non_applicable_membership_statuses() {
            let org_id = OrganizationId::new_v4();
            for status in [
                OrganizationUserStatusType::Invited,
                OrganizationUserStatusType::Revoked,
                OrganizationUserStatusType::Staged,
            ] {
                let label = format!("expected {status:?} to be dropped");
                let policies = vec![policy_view(org_id, PolicyType::MasterPassword, None)];
                let orgs = vec![OrganizationUserPolicyContext {
                    status,
                    ..confirmed_member(org_id)
                }];

                let result = filter(policies, orgs, PolicyType::MasterPassword);

                assert!(result.is_empty(), "{label}");
            }
        }

        #[test]
        fn keeps_the_policy_for_applicable_membership_statuses() {
            let org_id = OrganizationId::new_v4();
            for status in [
                OrganizationUserStatusType::Accepted,
                OrganizationUserStatusType::Confirmed,
            ] {
                let label = format!("expected {status:?} to be kept");
                let policies = vec![policy_view(org_id, PolicyType::MasterPassword, None)];
                let orgs = vec![OrganizationUserPolicyContext {
                    status,
                    ..confirmed_member(org_id)
                }];

                let result = filter(policies, orgs, PolicyType::MasterPassword);

                assert_eq!(result.len(), 1, "{label}");
            }
        }

        #[test]
        fn enforces_the_policy_by_default_when_the_org_is_absent_from_the_contexts() {
            let org_a = OrganizationId::new_v4();
            let org_b = OrganizationId::new_v4();
            let policies = vec![policy_view(org_a, PolicyType::MasterPassword, None)];

            // Only a context for a different org is provided.
            let result = filter(
                policies,
                vec![confirmed_member(org_b)],
                PolicyType::MasterPassword,
            );

            assert_eq!(result.len(), 1);
        }

        #[test]
        fn enforces_the_policy_by_default_when_the_contexts_are_empty() {
            let org_id = OrganizationId::new_v4();
            let policies = vec![policy_view(org_id, PolicyType::MasterPassword, None)];

            let result = filter(policies, vec![], PolicyType::MasterPassword);

            assert_eq!(result.len(), 1);
        }

        #[test]
        fn applies_master_password_to_an_owner() {
            // MasterPasswordPolicy has no exempt roles, so it applies even to an Owner.
            let org_id = OrganizationId::new_v4();
            let policies = vec![policy_view(org_id, PolicyType::MasterPassword, None)];
            let orgs = vec![OrganizationUserPolicyContext {
                role: OrganizationUserType::Owner,
                ..confirmed_member(org_id)
            }];

            let result = filter(policies, orgs, PolicyType::MasterPassword);

            assert_eq!(result.len(), 1);
        }

        #[test]
        fn exempts_an_owner_from_maximum_vault_timeout() {
            let org_id = OrganizationId::new_v4();
            let policies = vec![policy_view(org_id, PolicyType::MaximumVaultTimeout, None)];
            let orgs = vec![OrganizationUserPolicyContext {
                role: OrganizationUserType::Owner,
                ..confirmed_member(org_id)
            }];

            let result = filter(policies, orgs, PolicyType::MaximumVaultTimeout);

            assert!(result.is_empty());
        }

        #[test]
        fn applies_maximum_vault_timeout_to_admins_and_users() {
            let org_id = OrganizationId::new_v4();
            for role in [OrganizationUserType::Admin, OrganizationUserType::User] {
                let label = format!("expected {role:?} to be subject");
                let policies = vec![policy_view(org_id, PolicyType::MaximumVaultTimeout, None)];
                let orgs = vec![OrganizationUserPolicyContext {
                    role,
                    ..confirmed_member(org_id)
                }];

                let result = filter(policies, orgs, PolicyType::MaximumVaultTimeout);

                assert_eq!(result.len(), 1, "{label}");
            }
        }

        #[test]
        fn two_factor_authentication_exempts_owners_and_admins_via_default_impl() {
            let org_id = OrganizationId::new_v4();
            for role in [OrganizationUserType::Owner, OrganizationUserType::Admin] {
                let label = format!("expected {role:?} to be exempt");
                let policies = vec![policy_view(
                    org_id,
                    PolicyType::TwoFactorAuthentication,
                    None,
                )];
                let orgs = vec![OrganizationUserPolicyContext {
                    role,
                    ..confirmed_member(org_id)
                }];

                let result = filter(policies, orgs, PolicyType::TwoFactorAuthentication);

                assert!(result.is_empty(), "{label}");
            }
        }

        #[test]
        fn two_factor_authentication_applies_to_a_regular_user_via_default_impl() {
            let org_id = OrganizationId::new_v4();
            let policies = vec![policy_view(
                org_id,
                PolicyType::TwoFactorAuthentication,
                None,
            )];

            let result = filter(
                policies,
                vec![confirmed_member(org_id)],
                PolicyType::TwoFactorAuthentication,
            );

            assert_eq!(result.len(), 1);
        }

        #[test]
        fn filters_independently_across_multiple_organizations() {
            // org_a's member is a subject User; org_b's member is an Owner, exempt from
            // MaximumVaultTimeout.
            let org_a = OrganizationId::new_v4();
            let org_b = OrganizationId::new_v4();
            let policies = vec![
                policy_view(org_a, PolicyType::MaximumVaultTimeout, None),
                policy_view(org_b, PolicyType::MaximumVaultTimeout, None),
            ];
            let orgs = vec![
                confirmed_member(org_a),
                OrganizationUserPolicyContext {
                    role: OrganizationUserType::Owner,
                    ..confirmed_member(org_b)
                },
            ];

            let result = filter(policies, orgs, PolicyType::MaximumVaultTimeout);

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].organization_id, org_a);
        }
    }
}
