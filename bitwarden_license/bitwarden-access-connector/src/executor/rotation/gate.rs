//! The gate for target-side steps: lease, cancellation, session and connectivity checks.

use std::{sync::Arc, time::Duration};

use bitwarden_threading::cancellation_token::CancellationToken;
use chrono::{DateTime, Utc};
use tokio::time::Instant;

use super::AbortReason;
use crate::auth::session::{SessionError, SessionLost, SessionManager, SessionPhase};

/// Reads the time of the last successful server contact.
pub(crate) type LastOk = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Decides, before each target-side try, whether the attempt may proceed; see [`Gate::check`].
pub(super) struct Gate<'a> {
    pub(super) session: &'a SessionManager,
    pub(super) execute_by: Instant,
    pub(super) offline_grace: Duration,
    pub(super) last_ok: &'a (dyn Fn() -> Instant + Send + Sync),
    pub(super) cancel: &'a CancellationToken,
}

impl Gate<'_> {
    /// Waits until the attempt may start its next target-side try, or returns why it must abort.
    ///
    /// Runs before every try (via `with_retries_gated`), so it never interrupts a call in flight.
    /// Each pass checks, in order:
    ///
    /// 1. The lease and cancellation: past `execute_by` aborts as [`AbortReason::LeaseExpired`], a
    ///    cancelled run as [`AbortReason::Cancelled`].
    /// 2. The session phase. `Revoked` or `Closed` aborts as [`AbortReason::SessionLost`].
    ///    `Expired` or `Authenticating` renews the token via `bearer`, bounded by `execute_by`,
    ///    then re-checks; renewal that keeps failing until the deadline counts as lease expiry.
    /// 3. Connectivity: an `Active` session with no server contact for longer than `offline_grace`
    ///    waits for it to recover (see [`wait_for_connectivity`]), then re-checks.
    ///
    /// Only an `Active`, connected session within its lease returns `Ok`.
    pub(super) async fn check(&self) -> Result<(), AbortReason> {
        loop {
            lease_or_cancel(self.execute_by, self.cancel)?;

            match self.session.phase().await {
                SessionPhase::Revoked => {
                    return Err(AbortReason::SessionLost(SessionLost::Revoked));
                }
                SessionPhase::Closed => {
                    return Err(AbortReason::SessionLost(SessionLost::Closed));
                }
                SessionPhase::Expired | SessionPhase::Authenticating => {
                    // `bearer` renews the token, bounded by `execute_by`.
                    match self.session.bearer(Some(self.execute_by)).await {
                        Ok(_) => continue,
                        Err(SessionError::Lost(l)) => return Err(AbortReason::SessionLost(l)),
                        // Renewal kept failing until the deadline.
                        Err(SessionError::Transient(_)) => return Err(AbortReason::LeaseExpired),
                    }
                }
                SessionPhase::Active if (self.last_ok)().elapsed() > self.offline_grace => {
                    wait_for_connectivity(
                        self.execute_by,
                        self.offline_grace,
                        self.last_ok,
                        self.cancel,
                    )
                    .await?;
                }
                SessionPhase::Active => return Ok(()),
            }
        }
    }
}

/// Aborts if the lease has expired or the run is cancelled, lease first.
fn lease_or_cancel(execute_by: Instant, cancel: &CancellationToken) -> Result<(), AbortReason> {
    if Instant::now() >= execute_by {
        return Err(AbortReason::LeaseExpired);
    }
    if cancel.is_cancelled() {
        return Err(AbortReason::Cancelled);
    }
    Ok(())
}

/// Polls every second until connectivity is fresh, the lease expires, or the run is cancelled.
async fn wait_for_connectivity(
    execute_by: Instant,
    offline_grace: Duration,
    last_ok: &(dyn Fn() -> Instant + Send + Sync),
    cancel: &CancellationToken,
) -> Result<(), AbortReason> {
    loop {
        lease_or_cancel(execute_by, cancel)?;
        if last_ok().elapsed() <= offline_grace {
            return Ok(());
        }
        let remaining = execute_by.saturating_duration_since(Instant::now());
        let sleep = Duration::from_secs(1).min(remaining);
        if sleep.is_zero() {
            return Err(AbortReason::LeaseExpired);
        }
        tokio::select! {
            _ = tokio::time::sleep(sleep) => {}
            _ = cancel.cancelled() => return Err(AbortReason::Cancelled),
        }
    }
}

/// The furthest `execute_by` is allowed to lie ahead.
const MAX_LEASE: Duration = Duration::from_secs(24 * 60 * 60);

/// Converts a UTC `DateTime` to an [`Instant`]; past maps to now, far future caps at
/// `now + 24h`.
pub(super) fn datetime_to_instant(dt: DateTime<Utc>) -> Instant {
    Instant::now()
        + (dt - Utc::now())
            .to_std()
            .unwrap_or_default()
            .min(MAX_LEASE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_session;

    #[test]
    fn past_datetime_maps_to_now_or_earlier() {
        let past = Utc::now() - chrono::Duration::minutes(5);
        let instant = datetime_to_instant(past);
        assert!(instant <= Instant::now() + Duration::from_millis(100));
    }

    #[test]
    fn future_datetime_maps_to_future_instant() {
        let future = Utc::now() + chrono::Duration::minutes(5);
        let instant = datetime_to_instant(future);
        assert!(instant > Instant::now());
    }

    // `execute_by` has passed, so the gate aborts on the lease before checking the session.

    #[tokio::test]
    async fn gate_lease_expired_aborts() {
        let server = wiremock::MockServer::start().await;
        let session = make_session(&server).await;
        let execute_by = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap_or_else(Instant::now);

        let gate = Gate {
            session: &session,
            execute_by,
            offline_grace: Duration::from_secs(60),
            last_ok: &Instant::now,
            cancel: &CancellationToken::new(),
        };

        assert!(matches!(gate.check().await, Err(AbortReason::LeaseExpired)));
    }

    // Already cancelled, so the gate aborts before checking the session.

    #[tokio::test]
    async fn gate_cancelled_aborts() {
        let server = wiremock::MockServer::start().await;
        let session = make_session(&server).await;
        let cancel = CancellationToken::new();
        cancel.cancel();

        let gate = Gate {
            session: &session,
            execute_by: Instant::now() + Duration::from_secs(300),
            offline_grace: Duration::from_secs(60),
            last_ok: &Instant::now,
            cancel: &cancel,
        };

        assert!(matches!(gate.check().await, Err(AbortReason::Cancelled)));
    }

    // Connectivity is already fresh, so the wait returns immediately without sleeping.

    #[tokio::test(start_paused = true)]
    async fn wait_for_connectivity_already_fresh_returns_immediately() {
        let cancel = CancellationToken::new();
        let start = Instant::now();

        let result = wait_for_connectivity(
            start + Duration::from_secs(300),
            Duration::from_secs(60),
            &Instant::now,
            &cancel,
        )
        .await;

        assert!(matches!(result, Ok(())));
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    // Connectivity is stale for the first three polls and then recovers, so the wait polls once a
    // second and returns Ok.

    #[tokio::test(start_paused = true)]
    async fn wait_for_connectivity_recovers_after_polls() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cancel = CancellationToken::new();
        let grace = Duration::from_secs(60);
        let start = Instant::now();
        let stale = start.checked_sub(grace * 2).unwrap();
        let calls = AtomicUsize::new(0);
        let last_ok = move || {
            if calls.fetch_add(1, Ordering::SeqCst) < 3 {
                stale
            } else {
                Instant::now()
            }
        };

        let result =
            wait_for_connectivity(start + Duration::from_secs(300), grace, &last_ok, &cancel).await;

        assert!(matches!(result, Ok(())));
        assert_eq!(start.elapsed(), Duration::from_secs(3));
    }

    // Connectivity never recovers, so the wait aborts on the lease with the last sleep capped to
    // the remaining lease.

    #[tokio::test(start_paused = true)]
    async fn wait_for_connectivity_lease_expires_while_stale() {
        let cancel = CancellationToken::new();
        let grace = Duration::from_secs(60);
        let start = Instant::now();
        let stale = start.checked_sub(grace * 2).unwrap();

        let result = wait_for_connectivity(
            start + Duration::from_millis(3500),
            grace,
            &move || stale,
            &cancel,
        )
        .await;

        assert!(matches!(result, Err(AbortReason::LeaseExpired)));
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(3500));
        assert!(elapsed < Duration::from_millis(4500));
    }

    // Cancelled while sleeping between polls, so the wait aborts without waiting out the poll.

    #[tokio::test(start_paused = true)]
    async fn wait_for_connectivity_cancelled_mid_sleep() {
        let cancel = CancellationToken::new();
        let grace = Duration::from_secs(60);
        let start = Instant::now();
        let stale = start.checked_sub(grace * 2).unwrap();

        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            canceller.cancel();
        });

        let result = wait_for_connectivity(
            start + Duration::from_secs(300),
            grace,
            &move || stale,
            &cancel,
        )
        .await;

        assert!(matches!(result, Err(AbortReason::Cancelled)));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    // Already cancelled before the first poll, so the wait aborts immediately.

    #[tokio::test(start_paused = true)]
    async fn wait_for_connectivity_already_cancelled() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let grace = Duration::from_secs(60);
        let start = Instant::now();
        let stale = start.checked_sub(grace * 2).unwrap();

        let result = wait_for_connectivity(
            start + Duration::from_secs(300),
            grace,
            &move || stale,
            &cancel,
        )
        .await;

        assert!(matches!(result, Err(AbortReason::Cancelled)));
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}
