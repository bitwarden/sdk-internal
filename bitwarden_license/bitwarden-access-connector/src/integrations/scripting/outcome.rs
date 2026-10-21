//! Translation of a script run into the rotation outcome the vault is told about.

use bitwarden_pam::RotationFailureCode;

use super::{
    Operation,
    runner::{InvokeError, ScriptExit},
};
use crate::{
    error::{Retry, SafeDetail},
    integrations::{IntegrationError, TargetEffect},
};

/// Translates a [`ScriptRunner::run`](super::runner::ScriptRunner::run) result into a rotation
/// outcome, implementing the README's exit-code and timeout tables.
pub(crate) fn classify_outcome(
    outcome: Result<ScriptExit, InvokeError>,
    operation: Operation,
    timeout_secs: u64,
) -> Result<(), IntegrationError> {
    match outcome {
        Ok(ScriptExit::Code(0)) => Ok(()),
        Ok(exit) => Err(exit_error(exit, operation)),
        Err(InvokeError::Timeout) => Err(timeout_error(operation, timeout_secs)),
        Err(InvokeError::StdinWrite) => Err(script_io_error(operation, "ScriptStdinWriteFailed")),
        Err(InvokeError::Wait) => Err(script_io_error(operation, "ScriptWaitFailed")),
        Err(InvokeError::Serialize | InvokeError::Spawn) => Err(IntegrationError {
            retry: Retry::Permanent,
            effect: TargetEffect::NotApplied,
            code: RotationFailureCode::Internal,
            detail: SafeDetail::from_kind("ScriptSpawnError"),
        }),
    }
}

fn script_io_error(operation: Operation, kind: &'static str) -> IntegrationError {
    IntegrationError {
        retry: Retry::Permanent,
        effect: operation.effect_if_interrupted(),
        code: RotationFailureCode::Internal,
        detail: SafeDetail::from_kind(kind),
    }
}

fn timeout_error(operation: Operation, timeout_secs: u64) -> IntegrationError {
    IntegrationError {
        retry: Retry::Permanent,
        effect: operation.effect_on_timeout(),
        code: RotationFailureCode::ScriptTimeout,
        detail: SafeDetail::timed_out(timeout_secs),
    }
}

fn exit_error(exit: ScriptExit, operation: Operation) -> IntegrationError {
    let (retry, effect, detail) = match exit {
        ScriptExit::Code(1) => (
            Retry::Permanent,
            TargetEffect::NotApplied,
            SafeDetail::from_exit_code(1),
        ),
        ScriptExit::Code(2) => (
            Retry::Permanent,
            TargetEffect::Applied,
            SafeDetail::from_exit_code(2),
        ),
        ScriptExit::Code(3) => (
            Retry::Permanent,
            TargetEffect::Unknown,
            SafeDetail::from_exit_code(3),
        ),
        ScriptExit::Code(4) => (
            Retry::Transient,
            TargetEffect::NotApplied,
            SafeDetail::from_exit_code(4),
        ),
        // Unknown exit code or signal termination.
        other => {
            let detail = match other {
                ScriptExit::Code(n) => SafeDetail::from_exit_code(n),
                ScriptExit::Signal(Some(n)) => SafeDetail::from_signal(n),
                ScriptExit::Signal(None) => SafeDetail::from_kind("signal"),
            };
            (Retry::Permanent, operation.effect_if_interrupted(), detail)
        }
    };
    IntegrationError {
        retry,
        effect,
        code: RotationFailureCode::ScriptFailed,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_outcome_maps_the_exit_code_table() {
        let cases = [
            (1, Retry::Permanent, TargetEffect::NotApplied),
            (2, Retry::Permanent, TargetEffect::Applied),
            (3, Retry::Permanent, TargetEffect::Unknown),
            (4, Retry::Transient, TargetEffect::NotApplied),
        ];
        for (code, retry, effect) in cases {
            let err =
                classify_outcome(Ok(ScriptExit::Code(code)), Operation::Rotate, 60).unwrap_err();
            assert_eq!(err.retry, retry, "exit {code}");
            assert_eq!(err.effect, effect, "exit {code}");
            assert_eq!(err.code, RotationFailureCode::ScriptFailed, "exit {code}");
        }
        classify_outcome(Ok(ScriptExit::Code(0)), Operation::Rotate, 60).unwrap();
    }

    #[test]
    fn classify_outcome_reports_the_signal_number() {
        let err =
            classify_outcome(Ok(ScriptExit::Signal(Some(9))), Operation::Rotate, 60).unwrap_err();
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.effect, TargetEffect::Unknown);
        assert_eq!(err.code, RotationFailureCode::ScriptFailed);
        assert_eq!(err.detail.as_str(), "signal 9");
    }

    #[test]
    fn classify_outcome_names_a_signal_without_a_number() {
        let err =
            classify_outcome(Ok(ScriptExit::Signal(None)), Operation::Rotate, 60).unwrap_err();
        assert_eq!(err.detail.as_str(), "error kind: signal");
    }

    #[test]
    fn classify_outcome_signal_leaves_a_non_rotate_target_alone() {
        let err =
            classify_outcome(Ok(ScriptExit::Signal(Some(9))), Operation::Verify, 60).unwrap_err();
        assert_eq!(err.effect, TargetEffect::NotApplied);
    }

    #[test]
    fn classify_outcome_unknown_exit_code_effect_depends_on_the_operation() {
        for (operation, effect) in [
            (Operation::Rotate, TargetEffect::Unknown),
            (Operation::Verify, TargetEffect::NotApplied),
            (Operation::Terminate, TargetEffect::NotApplied),
        ] {
            let err = classify_outcome(Ok(ScriptExit::Code(99)), operation, 60).unwrap_err();
            assert_eq!(err.effect, effect, "{operation:?}");
        }
    }

    #[test]
    fn classify_outcome_timeout_effect_depends_on_the_operation() {
        for (operation, effect) in [
            (Operation::Rotate, TargetEffect::Unknown),
            (Operation::Verify, TargetEffect::Applied),
            (Operation::Terminate, TargetEffect::NotApplied),
        ] {
            let err = classify_outcome(Err(InvokeError::Timeout), operation, 60).unwrap_err();
            assert_eq!(
                err.code,
                RotationFailureCode::ScriptTimeout,
                "{operation:?}"
            );
            assert_eq!(err.effect, effect, "{operation:?}");
        }
    }

    #[test]
    fn classify_outcome_does_not_claim_rotate_left_the_target_alone() {
        for err in [InvokeError::StdinWrite, InvokeError::Wait] {
            let rotate = classify_outcome(Err(err.clone()), Operation::Rotate, 60).unwrap_err();
            assert_eq!(rotate.effect, TargetEffect::Unknown, "{err:?}");

            for operation in [Operation::Verify, Operation::Terminate] {
                let other = classify_outcome(Err(err.clone()), operation, 60).unwrap_err();
                assert_eq!(
                    other.effect,
                    TargetEffect::NotApplied,
                    "{err:?}/{operation:?}"
                );
            }
        }
    }

    #[test]
    fn classify_outcome_names_the_failing_stage() {
        let write =
            classify_outcome(Err(InvokeError::StdinWrite), Operation::Rotate, 60).unwrap_err();
        assert_eq!(write.detail.as_str(), "error kind: ScriptStdinWriteFailed");

        let wait = classify_outcome(Err(InvokeError::Wait), Operation::Rotate, 60).unwrap_err();
        assert_eq!(wait.detail.as_str(), "error kind: ScriptWaitFailed");
    }

    #[test]
    fn classify_outcome_reports_a_spawn_failure_as_internal() {
        let spawn = classify_outcome(Err(InvokeError::Spawn), Operation::Rotate, 60).unwrap_err();
        assert_eq!(spawn.code, RotationFailureCode::Internal);
        assert_eq!(spawn.detail.as_str(), "error kind: ScriptSpawnError");
    }
}
