//! The `PolicyDefinition` trait and the enforcement machinery built on top of it.

use std::collections::{HashMap, HashSet};

use bitwarden_core::OrganizationId;
use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use serde::de::DeserializeOwned;

use crate::{
    OrganizationUserPolicyContext, Policy,
    models::{PolicyDecision, PolicyDecisionErased, PolicyView},
    policy_type::{PolicyDataType, PolicyType},
};

/// Strongly typed representation of a specific policy type in rust.
///
/// By implementing this, you define:
/// - basic characteristics, such as the associated [`PolicyType`] and [`PolicyDataType`], and the
///   configuration data struct (if any)
/// - enforcement behavior, such as role exemptions.
///
/// The defaults match the most common Bitwarden policy: Provider users, owners and
/// administrators are exempt, and policies only apply to Accepted and Confirmed members.
pub(crate) trait PolicyDefinition: Send + Sync + 'static {
    /// Returns the policy type this definition handles.
    fn policy_type(&self) -> PolicyType;

    /// Erases the strongly-typed [`Data`](Self::Data) into the FFI-friendly
    /// [`PolicyDataType`].
    fn to_erased(&self, data: Self::Data) -> PolicyDataType;

    /// The strongly-typed data for this policy. The [`Default`] value is
    /// the fall-back whenever the policy is not enforced or the raw data could
    /// not be parsed.
    type Data: Default + DeserializeOwned;

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

    /// Returns the membership statuses that this policy should be enforced against.
    ///
    /// Defaults to [`Accepted`](OrganizationUserStatusType::Accepted) and
    /// [`Confirmed`](OrganizationUserStatusType::Confirmed).
    fn enforced_statuses(&self) -> &[OrganizationUserStatusType] {
        &[
            OrganizationUserStatusType::Accepted,
            OrganizationUserStatusType::Confirmed,
        ]
    }
}

/// Evaluates whether a [`PolicyDefinition`] is enforced against the current user.
pub(crate) trait EnforceablePolicy: PolicyDefinition {
    /// Constructs a new [`PolicyDecision`] for a specific organization, evaluating
    /// whether the policy should be enforced against the user or not.
    ///
    /// If the organization context is missing for the corresponding
    /// organization, it will be enforced by default (err on the side of
    /// enforcement).
    fn get_enforced(
        &self,
        organization_id: OrganizationId,
        policies: &[Policy],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> PolicyDecision<Self>
    where
        Self: Sized;

    /// Constructs a new [`PolicyDecision`] for all the user's organization, evaluating
    /// whether each organization's policy should be enforced against the user or not.
    ///
    /// This will always return a [`PolicyDecision`] for each organization.
    fn get_all_enforced(
        &self,
        policies: &[Policy],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<PolicyDecision<Self>>
    where
        Self: Sized;
}

impl<P: PolicyDefinition> EnforceablePolicy for P {
    fn get_enforced(
        &self,
        organization_id: OrganizationId,
        policies: &[Policy],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> PolicyDecision<P> {
        let resolved = policies
            .iter()
            .filter(|v| v.organization_id == organization_id)
            .find_map(|v| PolicyView::resolve(self, v));

        match resolved {
            // Matching policy of this type: evaluate
            Some(resolved) => {
                let contexts: HashMap<OrganizationId, &OrganizationUserPolicyContext> =
                    organization_user_policy_contexts
                        .iter()
                        .map(|ctx| (ctx.id, ctx))
                        .collect();

                resolved.into_enforced(self, &contexts)
            }
            // No matching policy of this type: not enforced
            None => PolicyDecision::not_enforced(organization_id),
        }
    }

    fn get_all_enforced(
        &self,
        policies: &[Policy],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<PolicyDecision<P>> {
        // Evaluate policies: turn each policy into a PolicyDecision
        let contexts: HashMap<OrganizationId, &OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .iter()
                .map(|ctx| (ctx.id, ctx))
                .collect();

        let mut enforced_policies: Vec<PolicyDecision<P>> = policies
            .iter()
            .filter_map(|v| PolicyView::resolve(self, v))
            .map(|resolved| resolved.into_enforced(self, &contexts))
            .collect();

        // Evaluate organizations: for each organization without a policy, create a PolicyDecision
        // for parity. This guarantees that every organization has an associated policy
        // decision.
        let context_organization_ids: HashSet<OrganizationId> = organization_user_policy_contexts
            .iter()
            .map(|c| c.id)
            .collect();
        let policy_organization_ids: HashSet<OrganizationId> = enforced_policies
            .iter()
            .map(|p| p.organization_id)
            .collect();
        let organizations_without_policies = context_organization_ids
            .difference(&policy_organization_ids)
            .map(|id| PolicyDecision::not_enforced(*id));

        enforced_policies.extend(organizations_without_policies);
        enforced_policies
    }
}

/// Object-safe erasure of [`PolicyDefinition`].
///
/// [`PolicyDefinition`] cannot be used as a trait object because it has an associated
/// [`Data`](PolicyDefinition::Data) type. This trait hides that type behind the
/// serializable [`PolicyDataType`], allowing evaluation of a `dyn PolicyDefinition`.
pub(crate) trait ErasedPolicy {
    /// Type erased variant of [`EnforceablePolicy::get_enforced`].
    fn get_enforced_erased(
        &self,
        organization_id: OrganizationId,
        policies: &[Policy],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> PolicyDecisionErased;

    /// Type erased variant of [`EnforceablePolicy::get_all_enforced`].
    fn get_all_enforced_erased(
        &self,
        policies: &[Policy],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<PolicyDecisionErased>;
}

impl<P: PolicyDefinition> ErasedPolicy for P {
    fn get_enforced_erased(
        &self,
        organization_id: OrganizationId,
        policies: &[Policy],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> PolicyDecisionErased {
        self.get_enforced(organization_id, policies, organization_user_policy_contexts)
            .into_erased(self)
    }

    fn get_all_enforced_erased(
        &self,
        policies: &[Policy],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<PolicyDecisionErased> {
        self.get_all_enforced(policies, organization_user_policy_contexts)
            .into_iter()
            .map(|decision| decision.into_erased(self))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::OrganizationId;

    use super::*;
    use crate::{
        MasterPasswordPolicy, MasterPasswordPolicyData, PolicyId, policy_type::PolicyDataType,
    };

    /// A minimal policy with no data, used to exercise the enforcement gates
    /// independently of any real policy's configuration. Overrides mirror the
    /// trait defaults so the gate tests do not depend on them.
    struct TestPolicy;
    impl PolicyDefinition for TestPolicy {
        type Data = ();

        fn policy_type(&self) -> PolicyType {
            PolicyType::SingleOrg
        }

        fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
            PolicyDataType::SingleOrg
        }

        fn exempt_roles(&self) -> &[OrganizationUserType] {
            &[OrganizationUserType::Owner, OrganizationUserType::Admin]
        }

        fn exempt_providers(&self) -> bool {
            true
        }

        fn enforced_statuses(&self) -> &[OrganizationUserStatusType] {
            &[
                OrganizationUserStatusType::Accepted,
                OrganizationUserStatusType::Confirmed,
            ]
        }
    }

    fn policy_view(
        organization_id: OrganizationId,
        policy_type: PolicyType,
        enabled: bool,
    ) -> Policy {
        Policy {
            id: PolicyId::new_v4(),
            organization_id,
            r#type: policy_type,
            data: None,
            enabled,
            revision_date: None,
        }
    }

    /// A confirmed, enabled, non-provider member a policy applies to — the baseline for the gate
    /// tests, which vary a single field via struct-update syntax, e.g.
    /// `OrganizationUserPolicyContext { role: Owner, ..confirmed_member(org) }`.
    fn confirmed_member(id: OrganizationId) -> OrganizationUserPolicyContext {
        OrganizationUserPolicyContext {
            id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: true,
            is_provider_user: false,
        }
    }

    mod get_enforced {
        use super::*;

        /// Convenience for the single-org gate tests: resolves against the org of the first view.
        /// Multi-org resolution is covered by
        /// `get_all_enforced::resolves_each_org_independently`.
        fn is_enforced(
            org_id: OrganizationId,
            views: &[Policy],
            contexts: &[OrganizationUserPolicyContext],
        ) -> bool {
            TestPolicy.get_enforced(org_id, views, contexts).enforced
        }

        #[test]
        fn enforced_for_confirmed_member() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, true)];
            assert!(is_enforced(org, &views, &[confirmed_member(org)]));
        }

        #[test]
        fn not_enforced_when_policy_disabled() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, false)];
            assert!(!is_enforced(org, &views, &[confirmed_member(org)]));
        }

        #[test]
        fn not_enforced_when_org_disabled() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, true)];
            let ctx = OrganizationUserPolicyContext {
                enabled: false,
                ..confirmed_member(org)
            };
            assert!(!is_enforced(org, &views, &[ctx]));
        }

        #[test]
        fn not_enforced_when_use_policies_false() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, true)];
            let ctx = OrganizationUserPolicyContext {
                use_policies: false,
                ..confirmed_member(org)
            };
            assert!(!is_enforced(org, &views, &[ctx]));
        }

        #[test]
        fn not_enforced_for_exempt_role() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, true)];
            for (label, role) in [
                ("Owner", OrganizationUserType::Owner),
                ("Admin", OrganizationUserType::Admin),
            ] {
                let ctx = OrganizationUserPolicyContext {
                    role,
                    ..confirmed_member(org)
                };
                assert!(
                    !is_enforced(org, &views, &[ctx]),
                    "role {label} should be exempt"
                );
            }
        }

        #[test]
        fn not_enforced_for_non_applicable_status() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, true)];
            for (label, status) in [
                ("Invited", OrganizationUserStatusType::Invited),
                ("Revoked", OrganizationUserStatusType::Revoked),
                ("Staged", OrganizationUserStatusType::Staged),
            ] {
                let ctx = OrganizationUserPolicyContext {
                    status,
                    ..confirmed_member(org)
                };
                assert!(
                    !is_enforced(org, &views, &[ctx]),
                    "status {label} should not be applicable"
                );
            }
        }

        #[test]
        fn enforced_for_applicable_status() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, true)];
            for (label, status) in [
                ("Accepted", OrganizationUserStatusType::Accepted),
                ("Confirmed", OrganizationUserStatusType::Confirmed),
            ] {
                let ctx = OrganizationUserPolicyContext {
                    status,
                    ..confirmed_member(org)
                };
                assert!(
                    is_enforced(org, &views, &[ctx]),
                    "status {label} should apply"
                );
            }
        }

        #[test]
        fn not_enforced_for_provider_user() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, true)];
            let ctx = OrganizationUserPolicyContext {
                is_provider_user: true,
                ..confirmed_member(org)
            };
            assert!(!is_enforced(org, &views, &[ctx]));
        }

        #[test]
        fn wrong_policy_type_is_not_enforced() {
            let org = OrganizationId::new_v4();
            // A view for a different policy type must not resolve for TestPolicy.
            let views = [policy_view(org, PolicyType::PasswordGenerator, true)];
            assert!(!is_enforced(org, &views, &[confirmed_member(org)]));
        }

        #[test]
        fn missing_org_context_enforces_enabled_policy_by_default() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, true)];
            assert!(is_enforced(org, &views, &[]));
        }

        #[test]
        fn missing_org_context_does_not_enforce_disabled_policy() {
            let org = OrganizationId::new_v4();
            let views = [policy_view(org, PolicyType::SingleOrg, false)];
            assert!(!is_enforced(org, &views, &[]));
        }

        // --- Data parsing via `PolicyView::resolve` (uses the real MasterPasswordPolicy)
        // ---

        fn mp_view(org: OrganizationId, data: Option<&str>) -> Policy {
            Policy {
                id: PolicyId::new_v4(),
                organization_id: org,
                r#type: PolicyType::MasterPassword,
                data: data.map(str::to_owned),
                enabled: true,
                revision_date: None,
            }
        }

        #[test]
        fn valid_data_is_parsed() {
            let org = OrganizationId::new_v4();
            let views = [mp_view(org, Some(r#"{"minComplexity":3,"minLength":12}"#))];
            let decision = MasterPasswordPolicy.get_enforced(org, &views, &[confirmed_member(org)]);
            assert!(decision.enforced);
            assert_eq!(decision.data.min_complexity, Some(3));
            assert_eq!(decision.data.min_length, Some(12));
        }

        #[test]
        fn missing_data_falls_back_to_default() {
            let org = OrganizationId::new_v4();
            let views = [mp_view(org, None)];
            let decision = MasterPasswordPolicy.get_enforced(org, &views, &[confirmed_member(org)]);
            assert!(decision.enforced);
            assert_eq!(decision.data, MasterPasswordPolicyData::default());
        }

        #[test]
        fn malformed_data_falls_back_to_default_without_panicking() {
            let org = OrganizationId::new_v4();
            let views = [mp_view(org, Some("not json"))];
            // Must not panic; the unparseable blob falls back to `Default` while the
            // enforcement decision is still evaluated normally.
            let decision = MasterPasswordPolicy.get_enforced(org, &views, &[confirmed_member(org)]);
            assert!(decision.enforced);
            assert_eq!(decision.data, MasterPasswordPolicyData::default());
        }

        #[test]
        fn data_is_defaulted_when_not_enforced() {
            let org = OrganizationId::new_v4();
            let views = [mp_view(org, Some(r#"{"minComplexity":3}"#))];
            // A revoked member: not enforced, so the parsed data is discarded in favor of the
            // default.
            let ctx = OrganizationUserPolicyContext {
                status: OrganizationUserStatusType::Revoked,
                ..confirmed_member(org)
            };
            let decision = MasterPasswordPolicy.get_enforced(org, &views, &[ctx]);
            assert!(!decision.enforced);
            assert_eq!(decision.data, MasterPasswordPolicyData::default());
        }

        // --- Data parsing for the more complex data-carrying policies ---

        fn typed_view(org: OrganizationId, policy_type: PolicyType, data: &str) -> Policy {
            Policy {
                id: PolicyId::new_v4(),
                organization_id: org,
                r#type: policy_type,
                data: Some(data.to_owned()),
                enabled: true,
                revision_date: None,
            }
        }

        #[test]
        fn maximum_vault_timeout_data_is_parsed() {
            use crate::{MaximumVaultTimeoutPolicy, VaultTimeoutAction, VaultTimeoutType};

            let org = OrganizationId::new_v4();
            let views = [typed_view(
                org,
                PolicyType::MaximumVaultTimeout,
                r#"{"type":"custom","minutes":480,"action":"logOut"}"#,
            )];
            let decision =
                MaximumVaultTimeoutPolicy.get_enforced(org, &views, &[confirmed_member(org)]);
            assert!(decision.enforced);
            assert_eq!(decision.data.timeout_type, Some(VaultTimeoutType::Custom));
            assert_eq!(decision.data.minutes, Some(480));
            assert_eq!(decision.data.action, Some(VaultTimeoutAction::LogOut));
        }

        #[test]
        fn password_generator_data_is_parsed() {
            use crate::{PasswordGeneratorPolicy, PasswordGeneratorType};

            let org = OrganizationId::new_v4();
            let views = [typed_view(
                org,
                PolicyType::PasswordGenerator,
                r#"{"overridePasswordType":"passphrase","minLength":14,"capitalize":true}"#,
            )];
            let decision =
                PasswordGeneratorPolicy.get_enforced(org, &views, &[confirmed_member(org)]);
            assert!(decision.enforced);
            assert_eq!(
                decision.data.override_password_type,
                Some(PasswordGeneratorType::Passphrase)
            );
            assert_eq!(decision.data.min_length, Some(14));
            assert_eq!(decision.data.capitalize, Some(true));
        }
    }

    mod get_all_enforced {
        use super::*;

        #[test]
        fn resolves_each_org_independently() {
            let org_a = OrganizationId::new_v4();
            let org_b = OrganizationId::new_v4();
            let views = [
                policy_view(org_a, PolicyType::SingleOrg, true),
                policy_view(org_b, PolicyType::SingleOrg, true),
            ];
            // org_a's member is a subject User; org_b's is an exempt Owner.
            let contexts = [
                confirmed_member(org_a),
                OrganizationUserPolicyContext {
                    role: OrganizationUserType::Owner,
                    ..confirmed_member(org_b)
                },
            ];

            // get_enforced selects the requested org's view and pairs it with that org's context,
            // ignoring the other org entirely.
            assert!(TestPolicy.get_enforced(org_a, &views, &contexts).enforced);
            assert!(!TestPolicy.get_enforced(org_b, &views, &contexts).enforced);

            // get_all_enforced yields one decision per view, each evaluated against its own org.
            let all = TestPolicy.get_all_enforced(&views, &contexts);
            assert_eq!(all.len(), 2);
            assert!(
                all.iter()
                    .find(|d| d.organization_id == org_a)
                    .expect("a decision for org_a")
                    .enforced
            );
            assert!(
                !all.iter()
                    .find(|d| d.organization_id == org_b)
                    .expect("a decision for org_b")
                    .enforced
            );
        }

        #[test]
        fn given_organization_without_policy_returns_unenforced_policy() {
            let org_a = OrganizationId::new_v4();
            let org_b = OrganizationId::new_v4();
            let org_c = OrganizationId::new_v4();

            // Matching policy for org_a only. org_b has a different policy and org_c has no
            // policies.
            let views = [
                policy_view(org_a, PolicyType::SingleOrg, true),
                policy_view(org_b, PolicyType::MasterPassword, true),
            ];

            let contexts = [
                confirmed_member(org_a),
                confirmed_member(org_b),
                confirmed_member(org_c),
            ];

            let result = TestPolicy.get_all_enforced(&views, &contexts);
            assert!(result.len() == 3);
            assert!(
                result
                    .iter()
                    .find(|p| p.organization_id == org_a)
                    .expect("a decision for org_a")
                    .enforced
            );
            assert!(
                !result
                    .iter()
                    .find(|p| p.organization_id == org_b)
                    .expect("a decision for org_b")
                    .enforced
            );
            assert!(
                !result
                    .iter()
                    .find(|p| p.organization_id == org_c)
                    .expect("a decision for org_c")
                    .enforced
            );
        }
    }
}
