//! Organization login cipher scene template

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::play::SceneTemplate;

/// Arguments for creating an organization-owned login cipher
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationLoginCipherArgs {
    /// The user creating the cipher
    pub user_id: Uuid,
    /// The owning organization
    pub organization_id: Uuid,
    /// The organization's symmetric key, base64-encoded
    pub organization_key_b64: String,
    /// Collections the cipher is assigned to
    pub collection_ids: Vec<Uuid>,
    /// Cipher name
    pub name: String,
    /// Login username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Login password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Login URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Whether the cipher gets its own item key, with its fields encrypted under it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_cipher_key: Option<bool>,
}

/// Result returned when creating an organization login cipher
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationLoginCipherResult {
    /// The cipher's ID
    pub cipher_id: Uuid,
}

/// An organization login cipher scene for testing
pub struct OrganizationLoginCipherScene;

impl SceneTemplate for OrganizationLoginCipherScene {
    type Arguments = OrganizationLoginCipherArgs;
    type Result = OrganizationLoginCipherResult;

    fn template_name() -> &'static str {
        "OrganizationLoginCipherScene"
    }
}
