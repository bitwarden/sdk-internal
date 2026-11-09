//! Single organization scene template

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::play::SceneTemplate;

/// The server's `PlanType` enum value for a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PlanType(pub i32);

impl PlanType {
    /// `PlanType.EnterpriseAnnually` in the server.
    pub const ENTERPRISE_ANNUALLY: Self = Self(20);
}

/// Optional overrides applied on top of the organization's initial values
///
/// `None` leaves the value as the seeder created it.
#[derive(Default, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationOverrides {
    /// Whether the organization can use Privileged Access Management
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_pam: Option<bool>,
}

/// Arguments for creating a single organization scene
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleOrganizationArgs {
    /// The user that becomes the confirmed owner
    pub owner_user_id: Uuid,
    /// The organization's plan
    pub plan_type: PlanType,
    /// Organization name (should be mangled for test isolation)
    pub name: String,
    /// Organization domain (should be mangled for test isolation)
    pub domain: String,
    /// Number of seats
    pub seats: i32,
    /// Overrides applied after the plan's defaults
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overrides: Option<OrganizationOverrides>,
}

/// Result returned when creating a single organization scene
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleOrganizationResult {
    /// The organization's ID
    pub organization_id: Uuid,
    /// The owner's organization user ID
    pub organization_user_id: Uuid,
    /// The organization's API key
    pub api_key: String,
    /// The organization's symmetric key, base64-encoded
    pub organization_key_b64: String,
}

/// A single organization scene for testing
pub struct SingleOrganizationScene;

impl SceneTemplate for SingleOrganizationScene {
    type Arguments = SingleOrganizationArgs;
    type Result = SingleOrganizationResult;

    fn template_name() -> &'static str {
        "SingleOrganizationScene"
    }
}
