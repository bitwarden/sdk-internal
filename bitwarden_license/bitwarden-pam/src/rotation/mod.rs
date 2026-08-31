//! PAM credential rotation operations.
//!
//! Credential rotation replaces a managed account's secret on a schedule (or on demand), writing
//! the new value into both the target system and the vault cipher that holds it. Three things have
//! to be configured for that to happen, and this module has a client for each:
//!
//! - An **access connector** ([`AccessConnectorsClient`]) - the unattended agent that performs
//!   rotations. Registering one hands it the organization key, wrapped under a one-time token; see
//!   `AccessConnectorsClient::register` for that contract.
//! - A **target system** ([`TargetSystemsClient`]) - the thing being rotated against, either an
//!   integration a connector drives ([`Automatic`](TargetSystemMethod::Automatic)) or a note that
//!   an operator will do it by hand ([`Manual`](TargetSystemMethod::Manual)). A connector must be
//!   assigned a target before it can rotate against it.
//! - A **rotation config** ([`RotationConfigsClient`]), surfaced to operators as a *managed
//!   credential* - the link between one vault cipher and one target-system account, carrying the
//!   schedule and the triggers.
//!
//! Every route lives under the server's `access-connectors` prefix. Note the vocabulary: the server
//! and this module say *access connector*, and the standalone agent that consumes the token is the
//! *rotation daemon*. They are the same actor seen from either end.
//!
//! # Reading a rotation's outcome
//!
//! A dispatch is a [`RotationJobView`], and each of a connector's goes at it is a
//! [`RotationAttemptView`]. An attempt reports the target system and the vault separately -
//! [`sync_state`](RotationAttemptView::sync_state) and
//! [`cipher_updated`](RotationAttemptView::cipher_updated) - because they can disagree.
//! [`Indeterminate`](RotationSyncState::Indeterminate) is the case to handle deliberately: the
//! target may or may not hold the new credential, and no vault write was attempted, so the two are
//! possibly out of step until the next rotation succeeds.
//!
//! # Forward compatibility
//!
//! Every enum here carries an `Unknown` variant, so a newer server naming a status this version
//! does not model degrades to an unrecognized value rather than failing a whole list. Writes are
//! the exception: sending `Unknown` back is refused with
//! [`RotationError::UnrecognizedVariant`], since the SDK cannot say what it would mean.
//!
//! # Where the rules live
//!
//! Requests are validated locally before being sent ([`RotationValidationError`]) so a malformed
//! name, an unsatisfiable password policy, or a cron that is not Quartz-shaped fails fast rather
//! than after a round trip. Two pieces of presentation logic live here as well, so every client
//! renders rotation the same way: [`preset_for_cron`] maps cron expressions to and from named
//! presets, and [`rotation_config_actions`] derives which actions a config currently offers. The
//! server remains authoritative on both - notably the minimum rotation interval, which is
//! deliberately not duplicated here.

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
    RotationConfigCreateRequest, RotationConfigDetailView, RotationConfigUpdateRequest,
    RotationConfigView, RotationConfigsClient,
};
pub use connectors::{
    AccessConnectorDetailView, AccessConnectorRegistrationView, AccessConnectorView,
    AccessConnectorsClient,
};
pub use error::RotationError;
pub use models::{
    AccessConnectorStatus, PasswordPolicy, RotationAttemptStatus, RotationAttemptView,
    RotationJobStatus, RotationJobView, RotationSource, RotationSyncState,
    SessionTerminationOutcome, TargetSystemKind, TargetSystemMethod, TargetSystemStatus,
};
pub use registration::{ConnectorToken, ConnectorTokenInvalidError};
pub use schedule::{
    QuartzSchedulePreset, RotationScheduleClient, is_likely_quartz_cron, preset_for_cron,
};
pub use target_systems::{
    TargetSystemCreateRequest, TargetSystemUpdateRequest, TargetSystemView, TargetSystemsClient,
};
pub use validate::RotationValidationError;

/// Entry point for PAM credential rotation.
///
/// Groups the three configuration surfaces rather than hanging eight accessors off
/// [`PamClient`](crate::PamClient), matching how the server groups the routes.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Clone, FromClient)]
pub struct RotationClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RotationClient {
    /// Access connector operations: register, list, enable/disable, delete, and target assignment.
    pub fn connectors(&self) -> AccessConnectorsClient {
        AccessConnectorsClient {
            // Registering a connector wraps the organization key for it, so this is the one
            // rotation sub-client that needs key material.
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
