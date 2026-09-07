//! PAM credential rotation operations.
//!
//! Credential rotation replaces a managed account's secret on schedule or on demand, writing
//! it into both the target system and the vault cipher. Three clients configure it:
//! [`AccessConnectorsClient`] (the unattended rotation agent), [`TargetSystemsClient`] (what's
//! being rotated against), and [`RotationConfigsClient`] (the cipher-to-target link).
//!
//! A dispatch is a [`RotationJob`]; each [`RotationAttempt`] reports the target and vault
//! outcomes separately via [`sync_state`](RotationAttempt::sync_state) and
//! [`cipher_updated`](RotationAttempt::cipher_updated), since they can disagree.
//!
//! Every enum carries an `Unknown` variant for forward compatibility; writing one back is
//! refused with [`RotationError::UnrecognizedVariant`]. Requests are validated locally
//! ([`RotationValidationError`]) before being sent.

use std::sync::Arc;

use bitwarden_core::{FromClient, client::ApiConfigurations, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

mod actions;
mod configs;
mod connectors;
mod error;
mod models;
mod registration;
mod schedule;
mod target_systems;
mod validate;

pub use actions::{RotationConfigActions, rotation_config_actions};
pub use configs::{
    RotationConfig, RotationConfigCreateRequest, RotationConfigDetail, RotationConfigUpdateRequest,
    RotationConfigsClient,
};
pub use connectors::{
    AccessConnector, AccessConnectorDetail, AccessConnectorRegistrationResponse,
    AccessConnectorsClient,
};
pub use error::RotationError;
pub use models::{
    AccessConnectorStatus, PasswordPolicy, RotationAttempt, RotationAttemptStatus, RotationJob,
    RotationJobStatus, RotationSource, RotationSyncState, SessionTerminationOutcome,
    TargetSystemKind, TargetSystemMethod, TargetSystemStatus,
};
pub use registration::{ConnectorToken, ConnectorTokenInvalidError};
pub use schedule::{
    QuartzSchedulePreset, RotationScheduleClient, is_likely_quartz_cron, preset_for_cron,
};
pub use target_systems::{
    TargetSystem, TargetSystemCreateRequest, TargetSystemUpdateRequest, TargetSystemsClient,
};
pub use validate::RotationValidationError;

/// Entry point for PAM credential rotation.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Clone, FromClient)]
pub struct RotationClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RotationClient {
    /// Access connector operations.
    pub fn connectors(&self) -> AccessConnectorsClient {
        AccessConnectorsClient {
            key_store: self.key_store.clone(),
            api_configurations: self.api_configurations.clone(),
        }
    }

    /// Target system operations.
    pub fn target_systems(&self) -> TargetSystemsClient {
        TargetSystemsClient {
            api_configurations: self.api_configurations.clone(),
        }
    }

    /// Managed credential (rotation config) operations.
    pub fn configs(&self) -> RotationConfigsClient {
        RotationConfigsClient {
            api_configurations: self.api_configurations.clone(),
        }
    }

    /// Quartz cron schedule helpers. Pure functions - no network access.
    pub fn schedule(&self) -> RotationScheduleClient {
        RotationScheduleClient
    }
}
