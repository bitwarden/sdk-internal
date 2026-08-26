//! Emergency access relationships between two user test vectors.

use bitwarden_crypto::UnsignedSharedKey;
use bitwarden_encoding::B64;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::SchemaVersioned;

/// A committed emergency access test vector: one grantor trusting one grantee with takeover.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmergencyAccessV1Vector {
    /// The on-disk schema version.
    pub schema_version: u32,
    /// Stable slug identifying this vector, matching its file name.
    pub name: String,
    /// What this vector is for, in prose.
    pub description: String,
    /// The emergency access record's id.
    pub id: Uuid,
    /// The `name` of the user vector that granted access.
    pub grantor_vector: String,
    /// The `name` of the user vector that received access.
    pub grantee_vector: String,
    /// The grantee's public key, SPKI DER.
    pub grantee_public_key: B64,
    /// The grantor's user key, sealed to the grantee's public key.
    pub grantor_user_key_sealed_to_grantee: UnsignedSharedKey,
}

impl SchemaVersioned for EmergencyAccessV1Vector {
    fn schema_version(&self) -> u32 {
        self.schema_version
    }
}
