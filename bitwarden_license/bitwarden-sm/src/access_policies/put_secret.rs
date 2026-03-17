// Stub: not yet wired into the public API (pending OpenAPI spec regeneration).
#![allow(dead_code)]

use bitwarden_core::client::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::access_policies::types::AccessPolicyEntry;

#[derive(Error, Debug)]
pub enum PutSecretAccessPoliciesError {
    #[error("Not implemented: {feature}")]
    NotImplemented { feature: &'static str },
}

/// Request to replace access policies on a secret. See
/// [`super::put_project::PutProjectAccessPoliciesRequest`] for the `None` vs `Some(vec![])` vs
/// `Some(vec![...])` semantics.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutSecretAccessPoliciesRequest {
    pub secret_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_access_policies: Option<Vec<AccessPolicyEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_access_policies: Option<Vec<AccessPolicyEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_access_policies: Option<Vec<AccessPolicyEntry>>,
}

/// PUT /secrets/{id}/access-policies stub.
///
/// NOTE: The `put_secret_access_policies` endpoint is not yet available in `bitwarden-api-api`
/// (the OpenAPI spec has not been regenerated after the server change). This stub returns
/// NotImplemented until the API spec is regenerated and a proper PUT call can be made.
pub fn put_secret_access_policies(
    _client: &Client,
    _request: &PutSecretAccessPoliciesRequest,
) -> Result<(), PutSecretAccessPoliciesError> {
    Err(PutSecretAccessPoliciesError::NotImplemented {
        feature: "put_secret access policies",
    })
}
