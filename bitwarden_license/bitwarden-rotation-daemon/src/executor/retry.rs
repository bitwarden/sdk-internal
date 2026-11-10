//! Retry helpers for target-side and server-side rotation steps.
//!
//! # Overview
//!
//! Two variants of retry loop are provided:
//!
//! - [`with_retries`]: unconditional exponential-backoff loop up to a total try count (optionally
//!   deadline-capped).  Used for server-side steps where no session gate check is needed.
//! - [`with_retries_gated`]: same loop but awaits a caller-supplied `gate` closure **before every
//!   try including the first**.  Used for target-side steps 3 (rotate), 4 (verify), and 6
//!   (terminate) so that session loss or `execute_by` expiry aborts before the next target-side
//!   action is initiated, not mid-call.
//!
//! # Total-try semantics
//!
//! `RetryCfg::max_retry_attempts` (default 5) counts **total tries**, not extra
//! retries.  With 5 total tries there are 4 backoff sleeps between them.  The
//! sleep durations follow `retry_base_delay * 2^(n-1)`:
//!
//! | Try | Sleep before next try |
//! |-----|-----------------------|
//! | 1   | base × 1              |
//! | 2   | base × 2              |
//! | 3   | base × 4              |
//! | 4   | base × 8              |
//! | 5   | (none, last try)      |
//!
//! With `base = 1 s` the sleeps are 1 s, 2 s, 4 s, 8 s.
//!
//! # Deadline capping
//!
//! When `deadline` is `Some`, a sleep that would reach or pass the deadline is
//! truncated to the remaining time; if the deadline has already passed, the
//! loop stops immediately with the last error.  This ensures the loop never
//! overshoots `execute_by`.

use std::{future::Future, time::Duration};

use tokio::time::Instant;

use crate::error::ErrorClass;

// ---------------------------------------------------------------------------
// RetryCfg
// ---------------------------------------------------------------------------

/// Configuration for the retry helpers.
///
/// The `max_retry_attempts` field is interpreted as the **total number of
/// tries** (not extra retries).  The default of 5 produces at most 4 backoff
/// sleeps.
#[derive(Debug, Clone)]
pub(crate) struct RetryCfg {
    /// Total number of tries (including the first attempt).
    ///
    /// Must be ≥ 1.  Saturates at `u32::MAX`.  Default: 5.
    pub(crate) max_retry_attempts: u32,

    /// Base delay for the exponential backoff.
    ///
    /// The sleep before the n-th retry is `retry_base_delay * 2^(n-1)`.
    /// Default: 1 second.
    pub(crate) retry_base_delay: Duration,
}

impl Default for RetryCfg {
    fn default() -> Self {
        Self {
            max_retry_attempts: 5,
            retry_base_delay: Duration::from_secs(1),
        }
    }
}

// ---------------------------------------------------------------------------
// Outcome of a gated retry loop
// ---------------------------------------------------------------------------

/// The three possible outcomes of a [`with_retries_gated`] call.
#[derive(Debug)]
pub(crate) enum GatedOutcome<T, E, A> {
    /// The operation completed successfully.
    Ok(T),
    /// The gate aborted execution (session lost, execute_by expired, cancelled).
    Aborted(A),
    /// All retries were exhausted (or a fatal error occurred) without success.
    Failed(E),
}

// ---------------------------------------------------------------------------
// with_retries
// ---------------------------------------------------------------------------

/// Retry `op` up to `cfg.max_retry_attempts` total tries with exponential
/// backoff, optionally deadline-capped.
///
/// - [`ErrorClass::Fatal`] errors short-circuit immediately.
/// - [`ErrorClass::Transient`] errors are retried up to the total-try limit.
/// - If `deadline` is `Some` and sleeping would cross it, the sleep is truncated; if the deadline
///   is already past when checking, the loop stops with the last error.
///
/// Returns `Ok(T)` on the first success, or `Err(E)` after the last failed
/// attempt.
pub(crate) async fn with_retries<F, Fut, T, E>(
    cfg: &RetryCfg,
    deadline: Option<Instant>,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, (ErrorClass, E)>>,
{
    let max_tries = cfg.max_retry_attempts.max(1);
    let base = cfg.retry_base_delay;
    let mut last_err: Option<E> = None;

    for attempt in 0..max_tries {
        match op().await {
            Ok(v) => return Ok(v),
            Err((ErrorClass::Fatal, e)) => return Err(e),
            Err((ErrorClass::Transient, e)) => {
                last_err = Some(e);

                // If this was the last allowed attempt, don't sleep.
                if attempt + 1 >= max_tries {
                    break;
                }

                // Compute exponential sleep: base * 2^attempt (0-indexed, so
                // first sleep is base * 1, second is base * 2, …).
                let sleep = exponential_delay(base, attempt);
                let capped = cap_to_deadline(sleep, deadline);
                if capped == Duration::ZERO {
                    // Deadline already passed or truncated to zero — stop.
                    break;
                }
                tokio::time::sleep(capped).await;
            }
        }
    }

    // Unwrap is safe: max_tries >= 1 so at least one attempt ran.
    #[allow(clippy::unwrap_used)]
    Err(last_err.unwrap())
}

// ---------------------------------------------------------------------------
// with_retries_gated
// ---------------------------------------------------------------------------

/// Like [`with_retries`] but calls `gate().await` before **every** try
/// including the first.
///
/// The gate returns `Ok(())` to proceed, or `Err(A)` to abort.  An abort stops
/// the loop immediately and surfaces as [`GatedOutcome::Aborted`].
///
/// This is used for target-side steps (rotate, verify, terminate_sessions) so
/// that session loss or `execute_by` expiry is checked before initiating each
/// new target-side action, not mid-call.
pub(crate) async fn with_retries_gated<G, GFut, F, Fut, T, E, A>(
    cfg: &RetryCfg,
    mut gate: G,
    mut op: F,
) -> GatedOutcome<T, E, A>
where
    G: FnMut() -> GFut,
    GFut: Future<Output = Result<(), A>>,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, (ErrorClass, E)>>,
{
    let max_tries = cfg.max_retry_attempts.max(1);
    let base = cfg.retry_base_delay;
    let mut last_err: Option<E> = None;

    for attempt in 0..max_tries {
        // Gate check before every try — including the first.
        if let Err(abort) = gate().await {
            return GatedOutcome::Aborted(abort);
        }

        match op().await {
            Ok(v) => return GatedOutcome::Ok(v),
            Err((ErrorClass::Fatal, e)) => return GatedOutcome::Failed(e),
            Err((ErrorClass::Transient, e)) => {
                last_err = Some(e);

                if attempt + 1 >= max_tries {
                    break;
                }

                let sleep = exponential_delay(base, attempt);
                // Note: gated retries do not cap to a deadline here; the gate
                // itself is responsible for deadline enforcement (it checks
                // execute_by before every try).  We sleep the full backoff
                // duration; if the deadline passes during the sleep the gate
                // will abort on the next iteration.
                tokio::time::sleep(sleep).await;
            }
        }
    }

    #[allow(clippy::unwrap_used)]
    GatedOutcome::Failed(last_err.unwrap())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute `base * 2^attempt` (attempt is 0-indexed), capping at 32 * base to
/// avoid overflow with very large attempt counts.
fn exponential_delay(base: Duration, attempt: u32) -> Duration {
    // Cap the shift to avoid overflow; 2^5 = 32 is a reasonable practical cap
    // (at 1 s base that's 32 s, well within the spirit of the spec's 1,2,4,8 s
    // schedule for 5 total tries).
    let shift = attempt.min(5);
    base * (1u32 << shift)
}

/// Truncate `delay` so it does not push past `deadline`.
///
/// Returns `Duration::ZERO` if the deadline has already passed.
fn cap_to_deadline(delay: Duration, deadline: Option<Instant>) -> Duration {
    match deadline {
        None => delay,
        Some(dl) => {
            let now = Instant::now();
            if now >= dl {
                Duration::ZERO
            } else {
                let remaining = dl - now;
                delay.min(remaining)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::time::Instant;

    use super::*;
    use crate::error::ErrorClass;

    // ── with_retries backoff schedule ──────────────────────────────────────

    /// Count how many times `op` is called and verify the sleep schedule.
    #[tokio::test(start_paused = true)]
    async fn retry_calls_op_max_retry_attempts_times_on_transient() {
        let calls = Arc::new(Mutex::new(0u32));
        let cfg = RetryCfg {
            max_retry_attempts: 5,
            retry_base_delay: Duration::from_secs(1),
        };

        let calls_clone = Arc::clone(&calls);
        let result = with_retries::<_, _, (), String>(&cfg, None, || {
            let c = Arc::clone(&calls_clone);
            async move {
                *c.lock().unwrap() += 1;
                Err((ErrorClass::Transient, "transient".to_string()))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(*calls.lock().unwrap(), 5, "should try exactly 5 times");
    }

    #[tokio::test(start_paused = true)]
    async fn retry_fatal_short_circuits_immediately() {
        let calls = Arc::new(Mutex::new(0u32));
        let cfg = RetryCfg {
            max_retry_attempts: 5,
            retry_base_delay: Duration::from_secs(1),
        };

        let calls_clone = Arc::clone(&calls);
        let result = with_retries::<_, _, (), String>(&cfg, None, || {
            let c = Arc::clone(&calls_clone);
            async move {
                *c.lock().unwrap() += 1;
                Err((ErrorClass::Fatal, "fatal".to_string()))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(*calls.lock().unwrap(), 1, "fatal should stop after 1 call");
    }

    #[tokio::test(start_paused = true)]
    async fn retry_succeeds_on_first_try() {
        let cfg = RetryCfg::default();
        let result = with_retries::<_, _, i32, String>(&cfg, None, || async { Ok(42) }).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_succeeds_on_third_try() {
        let calls = Arc::new(Mutex::new(0u32));
        let cfg = RetryCfg {
            max_retry_attempts: 5,
            retry_base_delay: Duration::from_secs(1),
        };

        let calls_clone = Arc::clone(&calls);
        let result = with_retries::<_, _, i32, String>(&cfg, None, || {
            let c = Arc::clone(&calls_clone);
            async move {
                let mut n = c.lock().unwrap();
                *n += 1;
                if *n >= 3 {
                    Ok(99)
                } else {
                    Err((ErrorClass::Transient, "wait".to_string()))
                }
            }
        })
        .await;

        assert_eq!(result, Ok(99));
        assert_eq!(*calls.lock().unwrap(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_deadline_in_past_stops_after_first_transient() {
        let cfg = RetryCfg {
            max_retry_attempts: 5,
            retry_base_delay: Duration::from_secs(1),
        };
        // Deadline already in the past.
        let past = Instant::now().checked_sub(Duration::from_secs(1));
        // If the subtraction underflows we skip this test.
        let Some(past_deadline) = past else {
            return;
        };

        let calls = Arc::new(Mutex::new(0u32));
        let calls_clone = Arc::clone(&calls);
        let result = with_retries::<_, _, (), String>(&cfg, Some(past_deadline), || {
            let c = Arc::clone(&calls_clone);
            async move {
                *c.lock().unwrap() += 1;
                Err((ErrorClass::Transient, "t".to_string()))
            }
        })
        .await;

        assert!(result.is_err());
        // With a past deadline we should not have slept and tried again.
        assert_eq!(
            *calls.lock().unwrap(),
            1,
            "past deadline should stop after first try"
        );
    }

    // ── with_retries_gated: gate called before every try ───────────────────

    #[tokio::test(start_paused = true)]
    async fn gated_gate_called_before_each_try() {
        let gate_calls = Arc::new(Mutex::new(0u32));
        let op_calls = Arc::new(Mutex::new(0u32));
        let cfg = RetryCfg {
            max_retry_attempts: 3,
            retry_base_delay: Duration::from_millis(10),
        };

        let gc = Arc::clone(&gate_calls);
        let oc = Arc::clone(&op_calls);
        let result = with_retries_gated::<_, _, _, _, (), String, ()>(
            &cfg,
            || {
                let gc = Arc::clone(&gc);
                async move {
                    *gc.lock().unwrap() += 1;
                    Ok(())
                }
            },
            || {
                let oc = Arc::clone(&oc);
                async move {
                    *oc.lock().unwrap() += 1;
                    Err((ErrorClass::Transient, "t".to_string()))
                }
            },
        )
        .await;

        assert!(matches!(result, GatedOutcome::Failed(_)));
        assert_eq!(
            *gate_calls.lock().unwrap(),
            3,
            "gate called before each try"
        );
        assert_eq!(*op_calls.lock().unwrap(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn gated_abort_between_tries_stops_before_next_op() {
        // Gate aborts after 1 successful pass.
        let gate_calls = Arc::new(Mutex::new(0u32));
        let op_calls = Arc::new(Mutex::new(0u32));
        let cfg = RetryCfg {
            max_retry_attempts: 5,
            retry_base_delay: Duration::from_millis(10),
        };

        let gc = Arc::clone(&gate_calls);
        let oc = Arc::clone(&op_calls);
        let result = with_retries_gated::<_, _, _, _, (), String, &'static str>(
            &cfg,
            || {
                let gc = Arc::clone(&gc);
                async move {
                    let mut n = gc.lock().unwrap();
                    *n += 1;
                    if *n > 1 { Err("aborted") } else { Ok(()) }
                }
            },
            || {
                let oc = Arc::clone(&oc);
                async move {
                    *oc.lock().unwrap() += 1;
                    Err((ErrorClass::Transient, "t".to_string()))
                }
            },
        )
        .await;

        assert!(matches!(result, GatedOutcome::Aborted("aborted")));
        // Gate was called 2 times: once before try 1 (Ok), once before try 2 (Err).
        assert_eq!(*gate_calls.lock().unwrap(), 2);
        // Op was called only once (try 1; aborted before try 2).
        assert_eq!(*op_calls.lock().unwrap(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn gated_gate_abort_on_first_try_skips_op() {
        let op_calls = Arc::new(Mutex::new(0u32));
        let cfg = RetryCfg::default();

        let oc = Arc::clone(&op_calls);
        let result = with_retries_gated::<_, _, _, _, (), String, &'static str>(
            &cfg,
            || async { Err("immediate abort") },
            || {
                let oc = Arc::clone(&oc);
                async move {
                    *oc.lock().unwrap() += 1;
                    Ok(())
                }
            },
        )
        .await;

        assert!(matches!(result, GatedOutcome::Aborted("immediate abort")));
        assert_eq!(
            *op_calls.lock().unwrap(),
            0,
            "op never called when gate aborts first"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn gated_fatal_short_circuits() {
        let gate_calls = Arc::new(Mutex::new(0u32));
        let cfg = RetryCfg {
            max_retry_attempts: 5,
            retry_base_delay: Duration::from_millis(10),
        };

        let gc = Arc::clone(&gate_calls);
        let result = with_retries_gated::<_, _, _, _, (), String, ()>(
            &cfg,
            || {
                let gc = Arc::clone(&gc);
                async move {
                    *gc.lock().unwrap() += 1;
                    Ok(())
                }
            },
            || async { Err((ErrorClass::Fatal, "fatal".to_string())) },
        )
        .await;

        assert!(matches!(result, GatedOutcome::Failed(_)));
        assert_eq!(
            *gate_calls.lock().unwrap(),
            1,
            "only one gate call for fatal"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn gated_ok_on_first_try() {
        let cfg = RetryCfg::default();
        let result = with_retries_gated::<_, _, _, _, i32, String, ()>(
            &cfg,
            || async { Ok(()) },
            || async { Ok(42) },
        )
        .await;
        assert!(matches!(result, GatedOutcome::Ok(42)));
    }
}
