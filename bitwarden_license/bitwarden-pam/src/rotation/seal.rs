//! Shared sealing/unsealing helpers for PAM target systems and rotation configs.
//!
//! Both [`crate::TargetSystemsClient`] and [`crate::RotationConfigsClient`] store their
//! security-relevant fields as opaque blobs sealed under the organization key (see
//! `docs/pam-rotation-sealed-config-plan.md`). Reading one back can fail in ways a hostile or
//! buggy server can trigger, none of which may fail the whole `list`, so this module centralizes
//! "unseal and validate, degrading to `None`" so both clients apply the same rules.

use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::KeyStoreContext;
use bitwarden_pam_sealed::{
    RotationConfigSealedV1, SealedTargetSystemMethod, TargetSystemSealedV1, unseal_rotation_config,
    unseal_target_system,
};
use uuid::Uuid;

use super::{
    configs::RotationConfigSealedFields,
    models::{TargetSystemMethod, TargetSystemStatus},
    target_systems::TargetSystemSealedFields,
};
use crate::{RotationConfigId, TargetSystemId};

/// Unseals a target system's blob and validates it against the row's own plaintext `id` and
/// `method`. Never fails outright: any problem degrades to `None` (so one bad item cannot fail a
/// `list`), logged at debug without field values.
///
/// `organization_id` must be the id the caller queried under, not one echoed back by the server:
/// trusting the server's copy would let it substitute another organization's validly-sealed blob
/// into this one's list.
pub(super) fn unseal_target(
    sealed_data: Option<&str>,
    status: TargetSystemStatus,
    target_system_id: TargetSystemId,
    method: TargetSystemMethod,
    organization_id: OrganizationId,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Option<TargetSystemSealedFields> {
    let invalid = |reason: &str| {
        tracing::debug!(reason, "PAM target system sealed blob rejected");
        None
    };

    if status == TargetSystemStatus::PendingSeal {
        // Expected, not a rejection: the two-phase creation has not sealed this row yet.
        return None;
    }

    let Some(blob) = sealed_data else {
        return invalid("missing blob");
    };

    let organization_key = SymmetricKeySlotId::Organization(organization_id);
    let unsealed = match unseal_target_system::<KeySlotIds>(blob, &organization_key, ctx) {
        Ok(unsealed) => unsealed,
        Err(_) => return invalid("unseal failed"),
    };

    if unsealed.target_system_id != Uuid::from(target_system_id) {
        return invalid("target_system_id mismatch");
    }

    let method_matches = matches!(
        (method, unsealed.method),
        (
            TargetSystemMethod::Automatic,
            SealedTargetSystemMethod::Automatic
        ) | (TargetSystemMethod::Manual, SealedTargetSystemMethod::Manual)
    );
    if !method_matches {
        return invalid("method mismatch");
    }

    Some(TargetSystemSealedFields {
        kind: unsealed.kind.map(Into::into),
        password_policy: unsealed.password_policy.into(),
        supports_session_termination: unsealed.supports_session_termination,
    })
}

/// Unseals a rotation config's blob and validates it against the row's own plaintext
/// `target_system_id` and `cipher_id`. Never fails outright: any problem degrades to `None`, so
/// one bad item cannot fail a `list`. Logs at debug, without field values.
///
/// `organization_id` must be the caller's queried id, not the server's — see [`unseal_target`].
pub(super) fn unseal_config(
    sealed_data: Option<&str>,
    config_id: RotationConfigId,
    target_system_id: TargetSystemId,
    cipher_id: Uuid,
    organization_id: OrganizationId,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Option<RotationConfigSealedFields> {
    let invalid = |reason: &str| {
        tracing::debug!(
            config_id = %config_id,
            reason,
            "PAM rotation config sealed blob rejected"
        );
        None
    };

    let Some(blob) = sealed_data else {
        return invalid("missing blob");
    };

    let organization_key = SymmetricKeySlotId::Organization(organization_id);
    let unsealed = match unseal_rotation_config::<KeySlotIds>(blob, &organization_key, ctx) {
        Ok(unsealed) => unsealed,
        Err(_) => return invalid("unseal failed"),
    };

    if unsealed.target_system_id != Uuid::from(target_system_id) {
        return invalid("target_system_id mismatch");
    }
    if unsealed.cipher_id != cipher_id {
        return invalid("cipher_id mismatch");
    }

    Some(RotationConfigSealedFields {
        account_identity: unsealed.account_identity,
        terminate_sessions: unsealed.terminate_sessions,
    })
}

/// Builds the sealed payload for a target system, binding it to `id` so the connector (and
/// [`unseal_target`]) can detect a blob swapped from another target.
pub(super) fn target_system_sealed_data(
    id: TargetSystemId,
    method: SealedTargetSystemMethod,
    kind: Option<bitwarden_pam_sealed::SealedTargetSystemKind>,
    password_policy: bitwarden_pam_sealed::SealedPasswordPolicy,
    supports_session_termination: Option<bool>,
) -> TargetSystemSealedV1 {
    TargetSystemSealedV1 {
        target_system_id: id.into(),
        method,
        kind,
        password_policy,
        supports_session_termination,
    }
}

/// Builds the sealed payload for a rotation config, binding it to `target_system_id` and
/// `cipher_id` so the connector (and [`unseal_config`]) can detect a blob swapped from another
/// config.
pub(super) fn rotation_config_sealed_data(
    target_system_id: TargetSystemId,
    cipher_id: Uuid,
    account_identity: String,
    terminate_sessions: bool,
) -> RotationConfigSealedV1 {
    RotationConfigSealedV1 {
        target_system_id: target_system_id.into(),
        cipher_id,
        account_identity,
        terminate_sessions,
    }
}
