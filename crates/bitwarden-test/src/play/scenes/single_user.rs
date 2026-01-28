//! Single user scene template

use serde::Serialize;
use uuid::Uuid;

use crate::play::SceneTemplate;

/// Arguments for creating a single user scene
#[derive(Default, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleUserArgs {
    /// User email address (should be mangled for test isolation)
    pub email: String,
    /// Whether the user's email is verified
    pub verified: bool,
    /// Whether the user has premium
    pub premium: bool,
    /// Optional user ID to set
    pub id: Option<Uuid>,
    /// Optional api key
    pub api_key: Option<String>,
}

/// A single user scene for testing
#[derive(Debug, Clone)]
pub struct SingleUserScene;

impl SceneTemplate for SingleUserScene {
    type Arguments = SingleUserArgs;
    type Result = ();

    fn template_name() -> &'static str {
        "SingleUserScene"
    }

    fn from_result(_result: Self::Result) -> Self {
        Self
    }
}
