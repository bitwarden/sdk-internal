//! The [`EnrichedPolicy`] model.
//!
//! An [`EnrichedPolicy`] is the strongly-typed counterpart to a
//! [`PolicyView`](crate::PolicyView): it carries the deserialized `policy.data`
//! payload (via [`EnrichedPolicyType`]) and knows how to evaluate whether it is
//! enforced against a given user.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
use uuid::Uuid;

use crate::{EnrichedPolicyType, OrganizationUserPolicyContext, PolicyView};

/// An organization policy - strongly typed with its data.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct EnrichedPolicy {
    /// The policy's unique ID.
    pub id: Uuid,
    /// The organization this policy belongs to.
    pub organization_id: Uuid,
    /// The type of policy, with its policy definition if applicable.
    pub r#type: EnrichedPolicyType,
    /// Whether the policy is enabled.
    pub enabled: bool,
    /// When the policy was last modified.
    pub revision_date: Option<DateTime<Utc>>,
}

impl EnrichedPolicy {
    /// Builds an [`EnrichedPolicy`] from a raw [`PolicyView`], deserializing its
    /// `data` payload into the strongly-typed [`EnrichedPolicyType`].
    pub fn from_policy_view(view: &PolicyView) -> EnrichedPolicy {
        EnrichedPolicy {
            id: view.id,
            organization_id: view.organization_id,
            enabled: view.enabled,
            revision_date: view.revision_date,
            r#type: EnrichedPolicyType::from_policy_type(view.r#type, view.data.as_deref()),
        }
    }

    /// Returns whether this policy is enforced against the user described by the
    /// given organization contexts, applying the policy definition's exemption
    /// and applicability rules.
    pub fn enforced(
        &self,
        organization_user_policy_contexts: &HashMap<Uuid, OrganizationUserPolicyContext>,
    ) -> bool {
        let org = organization_user_policy_contexts.get(&self.organization_id);
        let definition = self.r#type.to_policy_definition();

        self.enabled
            && match org {
                Some(org) => {
                    org.enabled
                        && org.use_policies
                        && definition.applicable_statuses().contains(&org.status)
                        && !definition.exempt_roles().contains(&org.role)
                        && !(org.is_provider_user && definition.exempt_providers())
                }
                None => true, // Unknown org: enforce by default
            }
    }
}
