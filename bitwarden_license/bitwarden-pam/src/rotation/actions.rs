//! Which actions a rotation config currently offers.

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::{
    configs::RotationConfigView,
    models::{TargetSystemMethod, TargetSystemStatus},
};

/// The actions a rotation config offers right now.
///
/// Computed together rather than one predicate at a time because a caller rendering a config always
/// needs all of them, and because they are not independent - `can_pause` and `can_resume` are
/// exclusive, and `can_rotate_now` and `can_record_manual` are decided by the same method field.
/// Deriving them in one place keeps a caller from showing a contradictory pair.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct RotationConfigActions {
    /// Whether an on-demand rotation may be dispatched.
    pub can_rotate_now: bool,
    /// Whether the operator may record an out-of-band rotation.
    pub can_record_manual: bool,
    /// Whether the account identity and delete actions are locked.
    pub mutations_locked: bool,
    /// Whether the config may be paused.
    pub can_pause: bool,
    /// Whether the config may be resumed.
    pub can_resume: bool,
}

/// Derives the actions a config offers, given the status of its target system.
///
/// `target_status` is `None` when the target system has not been loaded yet, which is the common
/// case on first paint - the configs list and the target-systems list are separate calls. Every
/// predicate that depends on it fails closed, so a config never offers a rotation the server would
/// then refuse.
pub fn rotation_config_actions(
    config: &RotationConfigView,
    target_status: Option<TargetSystemStatus>,
) -> RotationConfigActions {
    RotationConfigActions {
        // All four conditions are the server's own guard on dispatching a job. `Unknown` for either
        // the method or the status fails closed: this SDK cannot tell whether the server would
        // accept, so it does not invite the operator to find out.
        can_rotate_now: config.enabled
            && config.target_system_method == TargetSystemMethod::Automatic
            && target_status == Some(TargetSystemStatus::Active)
            && !config.has_active_job,
        can_record_manual: config.target_system_method == TargetSystemMethod::Manual,
        // A running job owns the credential until it resolves. Editing the account it rotates, or
        // deleting the config underneath it, would leave the target and the vault disagreeing.
        mutations_locked: config.has_active_job,
        can_pause: config.enabled,
        can_resume: !config.enabled,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use uuid::uuid;

    use super::*;
    use crate::{RotationConfigId, TargetSystemId};

    fn timestamp() -> DateTime<Utc> {
        "2026-01-01T00:00:00Z".parse().expect("a valid timestamp")
    }

    /// An automatic, enabled, idle config - the one shape that offers a rotation. Each test varies
    /// exactly one field so the failing condition is unambiguous.
    fn rotatable_config() -> RotationConfigView {
        RotationConfigView {
            id: RotationConfigId::new(uuid!("11111111-1111-1111-1111-111111111111")),
            organization_id: bitwarden_core::OrganizationId::new(uuid!(
                "22222222-2222-2222-2222-222222222222"
            )),
            cipher_id: bitwarden_vault::CipherId::new(uuid!(
                "33333333-3333-3333-3333-333333333333"
            )),
            target_system_id: TargetSystemId::new(uuid!("44444444-4444-4444-4444-444444444444")),
            target_system_name: "Prod SQL".to_string(),
            target_system_method: TargetSystemMethod::Automatic,
            account_identity: "svc_rotation".to_string(),
            terminate_sessions: false,
            schedule_cron: None,
            rotate_on_access_end: false,
            enabled: true,
            last_rotation_at: None,
            next_rotation_at: None,
            has_active_job: false,
            awaiting_manual_rotation: false,
            creation_date: timestamp(),
            revision_date: timestamp(),
        }
    }

    #[test]
    fn an_enabled_idle_automatic_config_on_an_active_target_can_rotate() {
        let actions =
            rotation_config_actions(&rotatable_config(), Some(TargetSystemStatus::Active));

        assert!(actions.can_rotate_now);
        assert!(!actions.can_record_manual);
        assert!(!actions.mutations_locked);
        assert!(actions.can_pause);
        assert!(!actions.can_resume);
    }

    #[test]
    fn a_paused_config_cannot_rotate_and_offers_resume_instead() {
        let config = RotationConfigView {
            enabled: false,
            ..rotatable_config()
        };

        let actions = rotation_config_actions(&config, Some(TargetSystemStatus::Active));

        assert!(!actions.can_rotate_now);
        assert!(!actions.can_pause);
        assert!(actions.can_resume);
    }

    #[test]
    fn a_config_with_a_job_in_flight_cannot_rotate_and_locks_mutations() {
        let config = RotationConfigView {
            has_active_job: true,
            ..rotatable_config()
        };

        let actions = rotation_config_actions(&config, Some(TargetSystemStatus::Active));

        assert!(!actions.can_rotate_now);
        assert!(actions.mutations_locked);
    }

    #[test]
    fn a_disabled_target_system_blocks_rotation() {
        let actions =
            rotation_config_actions(&rotatable_config(), Some(TargetSystemStatus::Disabled));

        assert!(!actions.can_rotate_now);
    }

    /// First paint: the configs list has arrived, the target-systems list has not. Offering a
    /// rotation here would let the operator dispatch a job against a target that turns out to be
    /// disabled.
    #[test]
    fn an_unloaded_target_system_blocks_rotation() {
        let actions = rotation_config_actions(&rotatable_config(), None);

        assert!(!actions.can_rotate_now);
    }

    #[test]
    fn a_manual_config_offers_record_manual_rather_than_rotate() {
        let config = RotationConfigView {
            target_system_method: TargetSystemMethod::Manual,
            ..rotatable_config()
        };

        let actions = rotation_config_actions(&config, Some(TargetSystemStatus::Active));

        assert!(!actions.can_rotate_now);
        assert!(actions.can_record_manual);
    }

    /// A newer server naming a method this SDK cannot model must not fall through to either branch:
    /// the operator would be offered an action the server may reject.
    #[test]
    fn an_unrecognized_method_offers_neither_rotation_action() {
        let config = RotationConfigView {
            target_system_method: TargetSystemMethod::Unknown,
            ..rotatable_config()
        };

        let actions = rotation_config_actions(&config, Some(TargetSystemStatus::Active));

        assert!(!actions.can_rotate_now);
        assert!(!actions.can_record_manual);
    }

    #[test]
    fn an_unrecognized_target_status_blocks_rotation() {
        let actions =
            rotation_config_actions(&rotatable_config(), Some(TargetSystemStatus::Unknown));

        assert!(!actions.can_rotate_now);
    }

    /// Pause and resume are complements, never both available and never both withheld.
    #[test]
    fn pause_and_resume_are_mutually_exclusive() {
        for enabled in [true, false] {
            let config = RotationConfigView {
                enabled,
                ..rotatable_config()
            };

            let actions = rotation_config_actions(&config, Some(TargetSystemStatus::Active));

            assert_ne!(actions.can_pause, actions.can_resume, "enabled: {enabled}");
        }
    }
}
