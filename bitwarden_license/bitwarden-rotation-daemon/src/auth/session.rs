//! Session state machine for the rotation daemon.
//!
//! [`SessionManager`] encodes the spec's `DaemonSession` state machine
//! (rotation-daemon.allium §DaemonSession):
//!
//! ```text
//! authenticating → active → expired → authenticating  (refresh cycle)
//!                         → revoked  (terminal: rejected credential)
//!                         → closed   (terminal: explicit shutdown)
//! ```
//!
//! Entering `Revoked` or `Closed` drops the bearer and replaces the key store with a fresh one.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bitwarden_crypto::KeyStore;
use tokio::sync::{Mutex, watch};

use crate::{
    auth::identity::{AuthError, AuthSuccess, IdentityClient},
    crypto::{DaemonKeySlotIds, DaemonKeyStore, unwrap_org_key},
    token::DaemonToken,
};

/// 5-minute proactive renewal margin (mirrors `TOKEN_RENEW_MARGIN_SECONDS` in
/// `crates/bitwarden-auth/src/token_management/middleware.rs:8`).
const TOKEN_RENEW_MARGIN_SECS: u64 = 5 * 60;

/// Base delay for renewal backoff (1 s, doubled each attempt, capped at 30 s).
const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Maximum single backoff sleep.
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Renewal attempt count for a `None` deadline.
const NO_DEADLINE_MAX_TRIES: u32 = 3;

/// Observable phases of the daemon session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionPhase {
    /// Credential exchange in progress.
    Authenticating,
    /// Access token valid; org key installed in the key store.
    Active,
    /// Token expired; a refresh is pending.
    Expired,
    /// Terminal: credential was rejected.  No further auth attempts will be made.
    Revoked,
    /// Terminal: [`SessionManager::close`] was called.
    Closed,
}

/// Terminal session-loss variants exposed to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionLost {
    /// The session was revoked (credential rejected).
    Revoked,
    /// The session was closed via [`SessionManager::close`].
    Closed,
}

/// Errors returned by [`SessionManager::bearer`] and [`SessionManager::force_refresh`].
#[derive(Debug)]
pub(crate) enum SessionError {
    /// The session is terminally lost (revoked or closed).
    Lost(SessionLost),
    /// A transient error prevented renewal (network, 5xx, etc.).
    Transient(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lost(l) => write!(f, "session lost: {l:?}"),
            Self::Transient(s) => write!(f, "transient renewal error: {s}"),
        }
    }
}

/// The mutable state protected by the session mutex.
struct SessionState {
    phase: SessionPhase,
    /// Bearer token present while `Active`.
    bearer: Option<String>,
    /// Monotonic instant at which the bearer expires (`Active` only).
    expires_at: Option<Instant>,
    /// Key store.  Replaced with a fresh empty store on terminal entry.
    key_store: Arc<DaemonKeyStore>,
    /// Sender for the phase watch channel.
    phase_tx: watch::Sender<SessionPhase>,
}

impl SessionState {
    /// Whether the stored bearer is within or past the proactive renewal margin.
    fn needs_renewal(&self) -> bool {
        match self.expires_at {
            Some(t) => {
                let margin = Duration::from_secs(TOKEN_RENEW_MARGIN_SECS);
                match t.checked_duration_since(Instant::now()) {
                    Some(remaining) => remaining <= margin,
                    None => true, // already expired
                }
            }
            None => true,
        }
    }

    /// Set the phase and broadcast it on the watch channel.
    fn set_phase(&mut self, phase: SessionPhase) {
        self.phase = phase;
        self.phase_tx.send_if_modified(|p| {
            *p = phase;
            true
        });
    }

    /// Apply a successful auth response: install bearer + expiry + org key.
    fn apply_success(&mut self, success: AuthSuccess, token: &DaemonToken) -> Result<(), String> {
        use bitwarden_sensitive_value::ExposeSensitive as _;

        let expires_at = Instant::now() + Duration::from_secs(success.expires_in);

        unwrap_org_key(
            &self.key_store,
            &token.encryption_key,
            &success.encrypted_payload,
        )
        .map_err(|e| e.to_string())?;

        // Bearer is exposed here only to store it internally; never logged.
        self.bearer = Some(success.access_token.expose().to_owned());
        self.expires_at = Some(expires_at);
        self.set_phase(SessionPhase::Active);
        Ok(())
    }

    /// Transition to a terminal state, dropping all secrets.
    fn enter_terminal(&mut self, lost: SessionLost) {
        let phase = match lost {
            SessionLost::Revoked => SessionPhase::Revoked,
            SessionLost::Closed => SessionPhase::Closed,
        };
        self.set_phase(phase);
        self.bearer = None;
        self.expires_at = None;
        // Replace key store with a fresh empty one; clears the Organization slot.
        self.key_store = Arc::new(KeyStore::default());
    }
}

/// Manages the daemon session lifecycle.
///
/// Wraps an [`IdentityClient`] and a [`DaemonToken`]; all mutable state is behind an
/// async `Mutex`, so at most one renewal is in flight at a time. `Debug` is
/// implemented manually to avoid leaking the token or bearer.
pub(crate) struct SessionManager {
    state: Mutex<SessionState>,
    identity: IdentityClient,
    token: DaemonToken,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager").finish_non_exhaustive()
    }
}

impl SessionManager {
    /// Build a new `SessionManager` and perform the initial authentication; an
    /// immediately rejected credential returns `Err(SessionError::Lost(Revoked))`,
    /// which callers should treat as a fatal startup failure.
    pub(crate) async fn new(
        identity: IdentityClient,
        token: DaemonToken,
    ) -> Result<Arc<Self>, SessionError> {
        let key_store = Arc::new(KeyStore::<DaemonKeySlotIds>::default());
        let (phase_tx, _phase_rx) = watch::channel(SessionPhase::Authenticating);

        let state = SessionState {
            phase: SessionPhase::Authenticating,
            bearer: None,
            expires_at: None,
            key_store,
            phase_tx,
        };

        let mgr = Arc::new(Self {
            state: Mutex::new(state),
            identity,
            token,
        });

        // Perform the initial authentication (force=true: no stored token to coalesce on).
        mgr.renew_with_backoff(None, true).await?;

        Ok(mgr)
    }

    /// The current session phase.
    pub(crate) async fn phase(&self) -> SessionPhase {
        self.state.lock().await.phase
    }

    /// The shared key store.
    pub(crate) async fn key_store(&self) -> Arc<DaemonKeyStore> {
        Arc::clone(&self.state.lock().await.key_store)
    }

    /// Obtain a valid bearer token, renewing as needed.
    ///
    /// Retries transient errors with capped backoff up to `deadline` ([`NO_DEADLINE_MAX_TRIES`]
    /// caps a `None` deadline); a rejected credential clears secrets and returns
    /// `Err(Lost(Revoked))`.
    pub(crate) async fn bearer(&self, deadline: Option<Instant>) -> Result<String, SessionError> {
        // Fast-path: check current state without holding the mutex across a
        // potential network call.
        {
            let guard = self.state.lock().await;
            match guard.phase {
                SessionPhase::Revoked => {
                    return Err(SessionError::Lost(SessionLost::Revoked));
                }
                SessionPhase::Closed => {
                    return Err(SessionError::Lost(SessionLost::Closed));
                }
                SessionPhase::Active if !guard.needs_renewal() => {
                    return Ok(guard.bearer.clone().unwrap_or_default());
                }
                _ => {}
            }
            // Guard is dropped here; another task may renew before it is re-acquired.
        }

        self.renew_with_backoff(deadline, false).await?;

        let guard = self.state.lock().await;
        Ok(guard.bearer.clone().unwrap_or_default())
    }

    /// Force a session refresh on the 401 path.
    ///
    /// A bearer already differing from `stale` means a concurrent task already renewed it (the
    /// `resolve_retry` pattern) and is returned as-is; a match forces an unconditional renewal.
    pub(crate) async fn force_refresh(
        &self,
        stale: &str,
        deadline: Option<Instant>,
    ) -> Result<String, SessionError> {
        {
            let guard = self.state.lock().await;
            match guard.phase {
                SessionPhase::Revoked => return Err(SessionError::Lost(SessionLost::Revoked)),
                SessionPhase::Closed => return Err(SessionError::Lost(SessionLost::Closed)),
                _ => {}
            }
            // resolve_retry pattern: reuse a token already changed by a concurrent task.
            if let Some(current) = &guard.bearer
                && current != stale
            {
                return Ok(current.clone());
            }
        }

        // force=true skips the active-and-fresh coalescing guard.
        self.renew_with_backoff(deadline, true).await?;

        let guard = self.state.lock().await;
        Ok(guard.bearer.clone().unwrap_or_default())
    }

    /// Transition to `Closed`, dropping all secrets.
    pub(crate) async fn close(&self) {
        let mut guard = self.state.lock().await;
        if !matches!(guard.phase, SessionPhase::Revoked | SessionPhase::Closed) {
            guard.enter_terminal(SessionLost::Closed);
        }
    }

    /// Attempt to renew the session with backoff, serialised via the mutex.
    ///
    /// The mutex is held across the network call, so at most one identity call runs at a time;
    /// it releases during the backoff sleep so `close()` can still run.
    async fn renew_with_backoff(
        &self,
        deadline: Option<Instant>,
        force: bool,
    ) -> Result<(), SessionError> {
        let mut delay = BACKOFF_BASE;
        let mut tries: u32 = 0;
        let mut first_attempt = true;

        loop {
            let mut guard = self.state.lock().await;

            // Terminal checks and coalescing short-circuits.
            match guard.phase {
                SessionPhase::Revoked => return Err(SessionError::Lost(SessionLost::Revoked)),
                SessionPhase::Closed => return Err(SessionError::Lost(SessionLost::Closed)),
                // Coalescing check, skipped on the first attempt under force=true.
                SessionPhase::Active if !(guard.needs_renewal() || force && first_attempt) => {
                    return Ok(());
                }
                _ => {}
            }
            first_attempt = false;

            guard.set_phase(SessionPhase::Authenticating);

            // Other callers of bearer() block here until the lock releases.
            let result = self.identity.authenticate(&self.token).await;

            match result {
                Ok(success) => {
                    guard
                        .apply_success(success, &self.token)
                        .map_err(SessionError::Transient)?;
                    // Log successful auth/refresh.  `force` on the first attempt
                    // distinguishes a forced 401-driven refresh from a proactive
                    // renewal; the difference is cosmetic to the operator.
                    if tries == 0 {
                        tracing::info!("session established (authentication succeeded)");
                    } else {
                        tracing::info!(
                            retry = tries,
                            "session renewed (re-authentication succeeded)"
                        );
                    }
                    return Ok(());
                }
                Err(AuthError::Rejected) => {
                    guard.enter_terminal(SessionLost::Revoked);
                    // Terminal; the executor logs the actionable message, this logs
                    // the phase transition.
                    tracing::warn!(
                        "session entered Revoked phase (credential rejected by identity server)"
                    );
                    return Err(SessionError::Lost(SessionLost::Revoked));
                }
                Err(AuthError::Transient(msg)) => {
                    let err_msg = msg;

                    tries += 1;
                    let max_tries = match deadline {
                        None => NO_DEADLINE_MAX_TRIES,
                        Some(_) => u32::MAX,
                    };

                    if tries >= max_tries {
                        guard.set_phase(SessionPhase::Expired);
                        tracing::warn!(
                            retry = tries,
                            "session renewal failed (transient): {err_msg}; giving up after {tries} attempts"
                        );
                        return Err(SessionError::Transient(err_msg));
                    }

                    guard.set_phase(SessionPhase::Expired);
                    drop(guard);

                    let sleep_dur = compute_sleep(delay, deadline);
                    if sleep_dur == Duration::ZERO {
                        tracing::warn!(
                            retry = tries,
                            "session renewal deadline exceeded before retry; last error: {err_msg}"
                        );
                        return Err(SessionError::Transient(
                            "renewal deadline exceeded".to_owned(),
                        ));
                    }
                    tracing::warn!(
                        retry = tries,
                        sleep_ms = sleep_dur.as_millis(),
                        "session renewal failed (transient): {err_msg}; retrying after {sleep_dur:?}"
                    );
                    tokio::time::sleep(sleep_dur).await;
                    delay = (delay * 2).min(BACKOFF_CAP);
                }
                Err(AuthError::Protocol) => {
                    let err_msg = "identity server returned unexpected response".to_owned();

                    tries += 1;
                    let max_tries = match deadline {
                        None => NO_DEADLINE_MAX_TRIES,
                        Some(_) => u32::MAX,
                    };

                    if tries >= max_tries {
                        guard.set_phase(SessionPhase::Expired);
                        tracing::warn!(
                            retry = tries,
                            "session renewal failed (protocol error): {err_msg}; giving up after {tries} attempts"
                        );
                        return Err(SessionError::Transient(err_msg));
                    }

                    // Set Expired so phase-watchers see a transient stall.
                    guard.set_phase(SessionPhase::Expired);
                    // Release the lock before sleeping.
                    drop(guard);

                    let sleep_dur = compute_sleep(delay, deadline);
                    if sleep_dur == Duration::ZERO {
                        tracing::warn!(
                            retry = tries,
                            "session renewal deadline exceeded before retry; last error: {err_msg}"
                        );
                        return Err(SessionError::Transient(
                            "renewal deadline exceeded".to_owned(),
                        ));
                    }
                    tracing::warn!(
                        retry = tries,
                        sleep_ms = sleep_dur.as_millis(),
                        "session renewal failed (protocol error): {err_msg}; retrying after {sleep_dur:?}"
                    );
                    tokio::time::sleep(sleep_dur).await;
                    delay = (delay * 2).min(BACKOFF_CAP);
                }
            }
        }
    }
}

/// Compute the sleep duration: `delay` capped by time remaining until `deadline`, or
/// `Duration::ZERO` after the deadline passes.
fn compute_sleep(delay: Duration, deadline: Option<Instant>) -> Duration {
    match deadline {
        None => delay.min(BACKOFF_CAP),
        Some(dl) => {
            let remaining = dl.checked_duration_since(Instant::now());
            match remaining {
                Some(r) if r > Duration::ZERO => delay.min(r).min(BACKOFF_CAP),
                _ => Duration::ZERO,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bitwarden_crypto::{
        KeyDecryptable, PrimitiveEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm,
        derive_shareable_key,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::{auth::identity::IdentityClient, crypto::DaemonSymmSlotId, token::DaemonToken};

    const VALID_TOKEN_STR: &str = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    fn test_token() -> DaemonToken {
        use std::str::FromStr;
        DaemonToken::from_str(VALID_TOKEN_STR).expect("valid token")
    }

    /// Derive the token's encryption key (C1 constants).
    fn token_encryption_key() -> SymmetricCryptoKey {
        use bitwarden_encoding::B64;
        let b64: B64 = "X8vbvA0bduihIDe/qrzIQQ==".parse().expect("valid b64");
        let key_bytes: Zeroizing<[u8; 16]> =
            Zeroizing::new(b64.as_bytes().try_into().expect("16 bytes"));
        SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            key_bytes,
            "accesstoken",
            Some("sm-access-token"),
        ))
    }

    /// Build the `encryptedPayload` value an identity server would return.
    fn make_encrypted_payload(
        token_key: &SymmetricCryptoKey,
        org_key: &SymmetricCryptoKey,
    ) -> String {
        let org_key_bytes = org_key.to_encoded();
        let org_key_b64 = bitwarden_encoding::B64::from(org_key_bytes.as_ref());
        let org_key_b64_str: String = org_key_b64.into();
        let payload_json = format!(r#"{{"encryptionKey":"{org_key_b64_str}"}}"#);
        use bitwarden_crypto::KeyEncryptable;
        let enc = payload_json
            .as_str()
            .encrypt_with_key(token_key)
            .expect("encrypt payload");
        enc.to_string()
    }

    fn success_response(
        bearer: &str,
        expires_in: u64,
        encrypted_payload: &str,
    ) -> ResponseTemplate {
        let body = format!(
            r#"{{"access_token":"{bearer}","expires_in":{expires_in},"encrypted_payload":"{encrypted_payload}"}}"#
        );
        ResponseTemplate::new(200)
            .set_body_string(body)
            .insert_header("content-type", "application/json")
    }

    fn rejected_response() -> ResponseTemplate {
        ResponseTemplate::new(400)
            .set_body_string(r#"{"error":"invalid_client"}"#)
            .insert_header("content-type", "application/json")
    }

    #[tokio::test]
    async fn successful_auth_populates_bearer_and_org_key() {
        let token_key = token_encryption_key();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let encrypted_payload = make_encrypted_payload(&token_key, &org_key);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("my-bearer", 3600, &encrypted_payload))
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let mgr = SessionManager::new(client, test_token())
            .await
            .expect("SessionManager::new");

        assert_eq!(mgr.phase().await, SessionPhase::Active);

        // bearer() must return the token without a second identity hit.
        let bearer = mgr.bearer(None).await.expect("bearer");
        assert_eq!(bearer, "my-bearer");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);

        // The org key must be installed: probe encrypt under the store.
        let store = mgr.key_store().await;
        let probe_enc = {
            let mut ctx = store.context();
            "probe-value"
                .encrypt(&mut ctx, DaemonSymmSlotId::Organization)
                .expect("encrypt probe")
        };
        let decrypted: String = probe_enc.decrypt_with_key(&org_key).expect("decrypt probe");
        assert_eq!(decrypted, "probe-value");
    }

    #[tokio::test]
    async fn expiry_margin_triggers_renewal() {
        // expires_in=0 → token is immediately past the renewal margin → renewal on
        // the first bearer() call.
        let token_key = token_encryption_key();
        let org_key1 = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload1 = make_encrypted_payload(&token_key, &org_key1);
        let org_key2 = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload2 = make_encrypted_payload(&token_key, &org_key2);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("first-token", 0, &payload1))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("second-token", 3600, &payload2))
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let mgr = SessionManager::new(client, test_token())
            .await
            .expect("SessionManager::new");

        let bearer = mgr.bearer(None).await.expect("bearer");
        assert_eq!(bearer, "second-token");
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn concurrent_bearer_calls_coalesce_to_single_renewal() {
        let token_key = token_encryption_key();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload = make_encrypted_payload(&token_key, &org_key);

        let server = MockServer::start().await;
        // Initial auth: expires immediately.
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("initial-tok", 0, &payload))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let org_key2 = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload2 = make_encrypted_payload(&token_key, &org_key2);
        // The single renewal: add a 50 ms delay so concurrent callers overlap.
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                success_response("renewed-tok", 3600, &payload2)
                    .set_delay(Duration::from_millis(50)),
            )
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let mgr = Arc::new(
            SessionManager::new(client, test_token())
                .await
                .expect("SessionManager::new"),
        );

        // Spawn 5 concurrent bearer() calls; all tokens are expired → all need renewal.
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let m = Arc::clone(&mgr);
                tokio::spawn(async move { m.bearer(None).await })
            })
            .collect();

        for h in handles {
            assert_eq!(h.await.expect("spawn").expect("bearer"), "renewed-tok");
        }

        // Exactly 2 identity hits: initial auth + exactly 1 renewal.
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn invalid_client_at_startup_returns_revoked() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(rejected_response())
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let result = SessionManager::new(client, test_token()).await;

        assert!(
            matches!(result, Err(SessionError::Lost(SessionLost::Revoked))),
            "expected Lost(Revoked), got {result:?}"
        );
    }

    #[tokio::test]
    async fn revoked_session_short_circuits_without_identity_hits() {
        let token_key = token_encryption_key();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload = make_encrypted_payload(&token_key, &org_key);

        let server = MockServer::start().await;
        // Initial auth succeeds.
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("tok", 3600, &payload))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // After that: rejected.
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(rejected_response())
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let mgr = SessionManager::new(client, test_token())
            .await
            .expect("first auth succeeds");

        // Trigger revocation via force_refresh.
        let _ = mgr.force_refresh("tok", None).await;
        assert_eq!(mgr.phase().await, SessionPhase::Revoked);

        let count_before = server.received_requests().await.unwrap().len();

        let err = mgr.bearer(None).await.expect_err("should be lost");
        assert!(matches!(err, SessionError::Lost(SessionLost::Revoked)));

        // No new identity hits after revocation.
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            count_before
        );
    }

    #[tokio::test]
    async fn close_transitions_to_closed_and_short_circuits() {
        let token_key = token_encryption_key();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload = make_encrypted_payload(&token_key, &org_key);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("tok", 3600, &payload))
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let mgr = SessionManager::new(client, test_token())
            .await
            .expect("auth");

        mgr.close().await;
        assert_eq!(mgr.phase().await, SessionPhase::Closed);

        let count_before = server.received_requests().await.unwrap().len();
        let err = mgr.bearer(None).await.expect_err("should be lost");
        assert!(matches!(err, SessionError::Lost(SessionLost::Closed)));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            count_before
        );
    }

    #[tokio::test]
    async fn secrets_cleared_on_revoked() {
        let token_key = token_encryption_key();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload = make_encrypted_payload(&token_key, &org_key);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("tok", 3600, &payload))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(rejected_response())
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let mgr = SessionManager::new(client, test_token())
            .await
            .expect("first auth");

        let _ = mgr.force_refresh("tok", None).await;
        assert_eq!(mgr.phase().await, SessionPhase::Revoked);

        let err = mgr.bearer(None).await.expect_err("must be lost");
        assert!(matches!(err, SessionError::Lost(SessionLost::Revoked)));

        let store = mgr.key_store().await;
        assert!(
            !store
                .context()
                .has_symmetric_key(DaemonSymmSlotId::Organization),
            "org key slot must be cleared after revocation"
        );
    }

    #[tokio::test]
    async fn secrets_cleared_on_closed() {
        let token_key = token_encryption_key();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload = make_encrypted_payload(&token_key, &org_key);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("tok", 3600, &payload))
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let mgr = SessionManager::new(client, test_token())
            .await
            .expect("auth");

        mgr.close().await;

        let store = mgr.key_store().await;
        assert!(
            !store
                .context()
                .has_symmetric_key(DaemonSymmSlotId::Organization),
            "org key slot must be cleared after close"
        );
    }

    #[tokio::test]
    async fn force_refresh_reuses_token_if_already_renewed() {
        // resolve_retry pattern: force_refresh compares the stored token against `stale` and
        // skips the identity call on a mismatch.
        let token_key = token_encryption_key();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload = make_encrypted_payload(&token_key, &org_key);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("fresh-tok", 3600, &payload))
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let mgr = SessionManager::new(client, test_token())
            .await
            .expect("auth");

        let count_after_init = server.received_requests().await.unwrap().len();

        // Stored token is "fresh-tok"; "old-stale-value" differs, so it's reused.
        let result = mgr
            .force_refresh("old-stale-value", None)
            .await
            .expect("force_refresh");
        assert_eq!(result, "fresh-tok");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            count_after_init,
            "no additional identity call should be made"
        );
    }

    #[tokio::test]
    async fn org_key_re_derived_on_every_refresh() {
        let token_key = token_encryption_key();
        let org_key1 = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload1 = make_encrypted_payload(&token_key, &org_key1);
        let org_key2 = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let payload2 = make_encrypted_payload(&token_key, &org_key2);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("tok1", 0, &payload1))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(success_response("tok2", 3600, &payload2))
            .mount(&server)
            .await;

        let client = IdentityClient::new(server.uri()).expect("client");
        let mgr = SessionManager::new(client, test_token())
            .await
            .expect("first auth");

        // Trigger renewal (expired token).
        let _bearer2 = mgr.bearer(None).await.expect("second bearer");

        let store = mgr.key_store().await;
        let probe_enc = {
            let mut ctx = store.context();
            "check-key"
                .encrypt(&mut ctx, DaemonSymmSlotId::Organization)
                .expect("encrypt")
        };

        // Must decrypt under org_key2 (new key), not org_key1 (old key).
        let ok: Result<String, _> = probe_enc.decrypt_with_key(&org_key2);
        assert!(ok.is_ok(), "probe must decrypt under the new org key");
        let fail: Result<String, _> = probe_enc.decrypt_with_key(&org_key1);
        assert!(
            fail.is_err(),
            "probe must NOT decrypt under the old org key"
        );
    }
}
