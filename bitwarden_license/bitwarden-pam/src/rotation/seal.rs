//! Sealing helpers shared by target systems and rotation configs.
//!
//! Unsealing never fails outright: any problem degrades to `None`, so one bad blob can't fail a
//! `list`. The key comes from the sealed model's `organization_id`, which must be the id the caller
//! queried under, never one echoed by the server, or a hostile server could pass off another
//! organization's validly-sealed blob.

use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
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

/// Unseals a target system's blob and checks it against the row's plaintext `id` and `method`.
pub(super) fn unseal_target(
    sealed_data: Option<&str>,
    status: TargetSystemStatus,
    target_system_id: TargetSystemId,
    method: TargetSystemMethod,
    key: SymmetricKeySlotId,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Option<TargetSystemSealedFields> {
    let invalid = |reason: &str| {
        tracing::debug!(reason, "PAM target system sealed blob rejected");
        None
    };

    if status == TargetSystemStatus::PendingSeal {
        // Not sealed yet; expected, so not logged as a rejection.
        return None;
    }

    let Some(blob) = sealed_data else {
        return invalid("missing blob");
    };

    let unsealed = match unseal_target_system::<KeySlotIds>(blob, &key, ctx) {
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

/// Unseals a rotation config's blob and checks it against the row's plaintext
/// `target_system_id` and `cipher_id`.
pub(super) fn unseal_config(
    sealed_data: Option<&str>,
    config_id: RotationConfigId,
    target_system_id: TargetSystemId,
    cipher_id: Uuid,
    key: SymmetricKeySlotId,
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

    let unsealed = match unseal_rotation_config::<KeySlotIds>(blob, &key, ctx) {
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

/// Binds the payload to `id` so a blob swapped from another target is detected.
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

/// Binds the payload to `target_system_id` and `cipher_id` so a blob swapped from another config
/// is detected.
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
