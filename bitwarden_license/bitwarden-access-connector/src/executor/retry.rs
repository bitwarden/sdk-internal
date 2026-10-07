//! Retry helpers for target-side and server-side rotation steps.

use std::{future::Future, time::Duration};

use tokio::time::Instant;

use crate::error::ErrorClass;

/// Configuration for the retry helpers.
#[derive(Debug, Clone)]
pub(crate) struct RetryCfg {
    /// Total tries including the first, so the default of 5 allows at most 4 backoff sleeps. Zero
    /// counts as one.
    pub(crate) max_retry_attempts: u32,

    /// The sleep before the n-th retry is `retry_base_delay * 2^(n-1)`, capped at 32x. Defaults to
    /// one second.
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

/// The outcome of a [`with_retries_gated`] call.
#[derive(Debug)]
pub(crate) enum GatedOutcome<T, E, A> {
    Ok(T),
    /// The gate aborted execution (session lost, execute_by expired, cancelled).
    Aborted(A),
    /// A fatal error, or the last transient error once the tries ran out.
    Failed(E),
}

/// Retry `op` with exponential backoff. [`ErrorClass::Fatal`] returns at once;
/// [`ErrorClass::Transient`] retries until the tries run out or `deadline` passes, with sleeps
/// truncated to it.
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

                if attempt + 1 >= max_tries {
                    break;
                }

                let sleep = exponential_delay(base, attempt);
                let capped = cap_to_deadline(sleep, deadline);
                if capped == Duration::ZERO {
                    break;
                }
                tokio::time::sleep(capped).await;
            }
        }
    }

    // Safe: reaching here means at least one transient error was recorded.
    #[allow(clippy::unwrap_used)]
    Err(last_err.unwrap())
}

/// Like [`with_retries`], but awaits `gate()` before every try, including the first; an abort
/// returns [`GatedOutcome::Aborted`]. Target-side steps use it so session loss or lease expiry
/// stops them between tries, never mid-call.
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
                // No deadline cap: the gate checks execute_by before the next try.
                tokio::time::sleep(sleep).await;
            }
        }
    }

    #[allow(clippy::unwrap_used)]
    GatedOutcome::Failed(last_err.unwrap())
}

/// `base * 2^attempt` for a 0-indexed attempt, capped at 32x to avoid overflow.
fn exponential_delay(base: Duration, attempt: u32) -> Duration {
    let shift = attempt.min(5);
    base * (1u32 << shift)
}

/// Truncate `delay` so it does not push past `deadline`, or `Duration::ZERO`
/// after the deadline passes.
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

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::time::Instant;

    use super::*;
    use crate::error::ErrorClass;

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
        let past = Instant::now().checked_sub(Duration::from_secs(1));
        // Skip this test on subtraction underflow.
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
        assert_eq!(
            *calls.lock().unwrap(),
            1,
            "past deadline should stop after first try"
        );
    }

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
        // Gate: before try 1 (Ok) and before try 2 (Err).
        assert_eq!(*gate_calls.lock().unwrap(), 2);
        // Op: try 1 only; aborted before try 2.
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
