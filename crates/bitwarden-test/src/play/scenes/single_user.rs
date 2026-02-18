//! Single user scene template

use bitwarden_crypto::EncString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::play::SceneTemplate;

/// Arguments for creating a single user scene
#[derive(Default, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleUserArgs {
    /// User email address (should be mangled for test isolation)
    pub email: String,
    /// User password
    pub password: String,
    /// Whether the user's email is verified
    pub email_verified: bool,
    /// Whether the user has premium
    pub premium: bool,
}

/// Result returned when creating a single user scene
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleUserResult {
    /// The user's ID
    pub user_id: Uuid,
    // kdf: KdfType;
    // dfIterations?: number;
    /// The user's encrypted symmetric key
    pub key: EncString,
    /// The user's public key (unencrypted)
    pub public_key: String,
    /// The user's encrypted private key
    pub private_key: EncString,
    /// The user's API key for authentication
    pub api_key: String,
}

/// A single user scene for testing
pub struct SingleUserScene;

impl SceneTemplate for SingleUserScene {
    type Arguments = SingleUserArgs;
    type Result = SingleUserResult;

    fn template_name() -> &'static str {
        "SingleUserScene"
    }
}
