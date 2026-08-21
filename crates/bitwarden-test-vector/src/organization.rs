//! The organization half of the test vectors: the organization key, its account-recovery key pair,
//! and which user vectors are members.

use bitwarden_core::OrganizationId;
use bitwarden_crypto::{EncString, UnsignedSharedKey};
use bitwarden_encoding::B64;
use serde::{Deserialize, Serialize};

use crate::{SchemaVersioned, VaultVector};

/// A committed organization test vector.
/// [`crate::AccountVector::organization_keys`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrganizationV1Vector {
    /// The on-disk schema version.
    pub schema_version: u32,
    /// Stable slug identifying this vector, matching its file name.
    pub name: String,
    /// What this vector is for, in prose.
    pub description: String,
    /// The organization's id.
    pub organization_id: OrganizationId,
    /// The organization's symmetric key, in the SDK's legacy key encoding.
    pub organization_key: B64,
    /// The organization key's COSE `kid`, hex encoded, or `None` if the algorithm carries none.
    pub organization_key_id: Option<String>,
    /// The organization's public key, SPKI DER. This is what
    /// `GET /organizations/{id}/public-key` returns, and what members enroll their
    /// account-recovery key against.
    pub public_key: B64,
    /// The organization's private key, wrapped by the organization key.
    pub wrapped_private_key: EncString,
    /// The organization's members.
    pub members: Vec<OrganizationV1MemberVector>,
    /// The organization's ciphers, encrypted and decrypted.
    #[serde(default)]
    pub vault: VaultVector,
}

impl SchemaVersioned for OrganizationV1Vector {
    fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

/// One member of an organization test vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrganizationV1MemberVector {
    /// The `name` of the user vector this member corresponds to.
    pub user_vector: String,
    /// The organization key, sealed to this member's public key.
    pub organization_key_sealed_to_member: UnsignedSharedKey,
    /// This member's user key sealed to the organization's public key, i.e. the account-recovery
    /// (admin password reset) enrollment. `None` when the member is not enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_recovery_key: Option<UnsignedSharedKey>,
}
