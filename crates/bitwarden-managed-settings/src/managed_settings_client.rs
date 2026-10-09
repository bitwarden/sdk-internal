use std::sync::{Arc, RwLock};

use bitwarden_core::Client;
use bitwarden_managed_settings_types::{ManagedSettingsError, ManagementProfile};
use tokio::sync::watch;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::normalize::profile_from_json;

/// Handle to the host system's Unified Endpoint Management profile.
///
/// The host application constructs one of these at boot and pushes profiles into it, and hands its
/// [`cell`](ManagedSettingsClient::cell) to
/// [`bitwarden_core::ClientBuilder::with_managed_profile`] so the SDK reads the same profile.
/// Clones share the underlying profile, change signal, and mirror destination, so an update pushed
/// through one clone is observed by all of them.
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct ManagedSettingsClient {
    profile: Arc<RwLock<Option<ManagementProfile>>>,
    /// Signalled after every applied update. Carries no value: a subscriber reads the current
    /// profile from the handle.
    changes: Arc<watch::Sender<()>>,
    /// Serializes pushes to the mirror destination, so the last push to arrive carries the newest
    /// profile.
    #[cfg(feature = "wasm")]
    push_lock: Arc<tokio::sync::Mutex<()>>,
    #[cfg(feature = "wasm")]
    mirror_destination: Arc<RwLock<Option<Arc<crate::mirror::MirrorDestination>>>>,
}

impl Default for ManagedSettingsClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Methods whose signatures cannot cross an FFI boundary, so they stay off the binding surface.
impl ManagedSettingsClient {
    /// A handle onto an existing cell. It has its own change signal and no mirror destination, so
    /// an update made through it is not signalled to subscribers of the host's handle, nor pushed.
    pub(crate) fn from_profile(profile: Arc<RwLock<Option<ManagementProfile>>>) -> Self {
        Self {
            profile,
            changes: Arc::new(watch::Sender::new(())),
            #[cfg(feature = "wasm")]
            push_lock: Default::default(),
            #[cfg(feature = "wasm")]
            mirror_destination: Default::default(),
        }
    }

    /// The shared profile cell, for handing to
    /// [`bitwarden_core::ClientBuilder::with_managed_profile`] so a constructed SDK client reads
    /// the same profile the host pushes into this handle.
    pub fn cell(&self) -> Arc<RwLock<Option<ManagementProfile>>> {
        self.profile.clone()
    }

    /// The active profile, or `None` when the host has not pushed one.
    pub fn current_profile(&self) -> Option<ManagementProfile> {
        self.profile
            .read()
            .expect("managed-settings cell poisoned")
            .clone()
    }

    /// A receiver that is marked changed after every update applied to this handle or its clones.
    /// Updates applied in quick succession can be observed as one change.
    pub fn changes(&self) -> watch::Receiver<()> {
        self.changes.subscribe()
    }

    /// Replaces the active profile and signals subscribers, without pushing it to a mirror
    /// destination.
    pub(crate) fn apply(&self, profile: Option<ManagementProfile>) {
        match &profile {
            Some(p) => tracing::info!(
                version = p.version,
                keys = p.settings.len(),
                "Managed settings profile updated"
            ),
            None => tracing::info!("Managed settings profile cleared"),
        }

        *self
            .profile
            .write()
            .expect("managed-settings cell poisoned") = profile;
        self.changes.send_replace(());
    }

    /// Sends the current profile to the mirror destination, when one is set. A failed push is
    /// logged rather than returned, because a mirror that starts again requests the current
    /// profile.
    #[cfg(feature = "wasm")]
    async fn push_to_mirror_destination(&self) {
        use bitwarden_ipc::IpcClientExt;

        let Some(destination) = self
            .mirror_destination
            .read()
            .expect("managed-settings mirror destination poisoned")
            .clone()
        else {
            return;
        };

        let _guard = self.push_lock.lock().await;
        // Read under the lock, so a push that waited behind another carries the newest profile.
        let profile = self.current_profile();
        if let Err(error) = destination
            .ipc_client
            .send_typed(
                crate::mirror::ManagedProfilePush { profile },
                destination.endpoint.clone(),
            )
            .await
        {
            tracing::warn!(
                destination = ?destination.endpoint,
                ?error,
                "Failed to push the managed profile to the mirror destination"
            );
        }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ManagedSettingsClient {
    /// Fresh handle with no active profile. The host should call this once at boot.
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self::from_profile(Arc::new(RwLock::new(None)))
    }

    /// Replace the active profile. Clear the profile with `None`.
    ///
    /// The profile is applied before any await, so local reads never wait on IPC. When
    /// [`mirror_to`](ManagedSettingsClient::mirror_to) has set a destination, the profile is then
    /// pushed to it.
    // Only WASM builds can mirror, so other builds have nothing to await. The method stays async so
    // every binding shares one signature.
    #[cfg_attr(not(feature = "wasm"), allow(clippy::unused_async))]
    pub async fn update_profile(&self, profile: Option<ManagementProfile>) {
        self.apply(profile);
        #[cfg(feature = "wasm")]
        self.push_to_mirror_destination().await;
    }

    /// Normalize an administrator's settings object, given as a JSON string, into a profile and
    /// apply it like [`update_profile`](ManagedSettingsClient::update_profile). Nested objects
    /// become dotted keys, and every other value is stored JSON-encoded. `None` clears the profile.
    ///
    /// Input that is not valid JSON, or whose top level is not an object, also clears the profile,
    /// so a malformed value never leaves a fragment or a stale profile active. The returned error
    /// says why the input was rejected.
    pub async fn update_from_json(&self, json: Option<String>) -> Result<(), ManagedSettingsError> {
        let (profile, result) = match json.as_deref().map(profile_from_json) {
            None => (None, Ok(())),
            Some(Ok(profile)) => (Some(profile), Ok(())),
            Some(Err(error)) => (None, Err(error)),
        };
        self.update_profile(profile).await;
        result
    }

    /// Returns `true` if `key` is present in the active profile.
    pub fn is_managed(&self, key: String) -> bool {
        self.profile
            .read()
            .expect("managed-settings cell poisoned")
            .as_ref()
            .is_some_and(|p| p.is_managed(&key))
    }

    /// Raw JSON-encoded value for `key`, if a value is present.
    pub fn get(&self, key: String) -> Option<String> {
        self.profile
            .read()
            .expect("managed-settings cell poisoned")
            .as_ref()
            .and_then(|p| p.get(&key))
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl ManagedSettingsClient {
    /// Answers profile requests from `destination`, refuses them from any other peer, and pushes
    /// every later profile update to `destination`. The mirror lasts for the lifetime of
    /// `ipc_client`; the handler cannot be unregistered.
    pub async fn mirror_to(
        &self,
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
        destination: bitwarden_ipc::Endpoint,
    ) {
        use bitwarden_ipc::IpcClientExt;

        ipc_client
            .client
            .register_rpc_handler(crate::mirror::ManagedProfileRequestHandler {
                client: self.clone(),
                destination: destination.clone(),
            })
            .await;
        *self
            .mirror_destination
            .write()
            .expect("managed-settings mirror destination poisoned") =
            Some(Arc::new(crate::mirror::MirrorDestination {
                ipc_client: ipc_client.client.clone(),
                endpoint: destination,
            }));
    }

    /// Keeps this client's profile in sync with the client at `authority`. Subscribes to pushes,
    /// then requests the current profile once, with a timeout. A response that arrives after a
    /// push has been applied is dropped. Messages from any other source are rejected. Returns
    /// once subscribed; receiving continues for the lifetime of the IPC client.
    ///
    /// Fails when `ipc_client` has not been started.
    pub async fn mirror_from(
        &self,
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
        authority: bitwarden_ipc::Endpoint,
    ) -> Result<(), bitwarden_ipc::SubscribeError> {
        crate::mirror::mirror_from(self.clone(), ipc_client.client.clone(), authority).await
    }

    /// Calls `callback` after the profile changes, until `abort_signal` aborts. The callback
    /// receives no arguments; read the current values with
    /// [`get`](ManagedSettingsClient::get) and [`is_managed`](ManagedSettingsClient::is_managed).
    ///
    /// Updates applied in quick succession can result in a single call. The callback is not called
    /// for the profile that is active when it is registered.
    pub fn on_profile_changed(
        &self,
        #[wasm_bindgen(unchecked_param_type = "() => void")] callback: js_sys::Function,
        abort_signal: Option<bitwarden_threading::cancellation_token::wasm::AbortSignal>,
    ) {
        use bitwarden_threading::cancellation_token::wasm::AbortSignalExt;

        let mut changes = self.changes();
        let cancellation_token = abort_signal
            .map(|signal| signal.to_cancellation_token())
            .unwrap_or_default();

        wasm_bindgen_futures::spawn_local(async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => break,
                    changed = changes.changed() => {
                        // Every handle sharing the signal has been dropped, so no change can follow.
                        if changed.is_err() {
                            break;
                        }
                        if let Err(error) = callback.call0(&JsValue::NULL) {
                            tracing::warn!(?error, "Managed settings change callback threw");
                        }
                    }
                }
            }
        });
    }
}

/// Read the UEM profile handle back from a constructed [`bitwarden_core::Client`].
pub trait ManagedSettingsClientExt {
    /// Administrator-enforced settings operations.
    fn managed_settings(&self) -> ManagedSettingsClient;
}

impl ManagedSettingsClientExt for Client {
    fn managed_settings(&self) -> ManagedSettingsClient {
        ManagedSettingsClient::from_profile(self.internal.managed_profile_handle())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitwarden_core::ClientBuilder;

    use super::*;

    fn profile_with(key: &str, json_value: &str) -> ManagementProfile {
        ManagementProfile {
            version: 1,
            updated_at: 1_750_000_000,
            settings: HashMap::from([(key.to_string(), json_value.to_string())]),
        }
    }

    #[test]
    fn a_new_client_manages_nothing() {
        let client = ManagedSettingsClient::new();

        assert_eq!(client.get("environment.base".to_string()), None);
        assert!(!client.is_managed("environment.base".to_string()));
        assert_eq!(client.current_profile(), None);
    }

    #[tokio::test]
    async fn get_reflects_an_updated_profile() {
        let client = ManagedSettingsClient::new();
        let profile = profile_with("environment.base", "\"https://vault.example.com\"");

        client.update_profile(Some(profile.clone())).await;

        assert_eq!(
            client.get("environment.base".to_string()),
            Some("\"https://vault.example.com\"".to_string())
        );
        assert!(client.is_managed("environment.base".to_string()));
        assert_eq!(client.current_profile(), Some(profile));
    }

    #[tokio::test]
    async fn updating_with_none_clears_the_profile() {
        let client = ManagedSettingsClient::new();
        client
            .update_profile(Some(profile_with("environment.base", "\"https://a\"")))
            .await;

        client.update_profile(None).await;

        assert_eq!(client.get("environment.base".to_string()), None);
        assert!(!client.is_managed("environment.base".to_string()));
        assert_eq!(client.current_profile(), None);
    }

    #[tokio::test]
    async fn a_clone_observes_an_update_made_on_the_original() {
        let client = ManagedSettingsClient::new();
        let clone = client.clone();
        let profile = profile_with("environment.base", "\"https://vault.example.com\"");

        client.update_profile(Some(profile.clone())).await;

        assert_eq!(
            clone.get("environment.base".to_string()),
            Some("\"https://vault.example.com\"".to_string())
        );
        assert_eq!(clone.current_profile(), Some(profile));
    }

    #[tokio::test]
    async fn the_shared_cell_observes_an_update_made_through_the_handle() {
        let client = ManagedSettingsClient::new();
        let cell = client.cell();
        let profile = profile_with("environment.base", "\"https://vault.example.com\"");

        client.update_profile(Some(profile.clone())).await;

        assert_eq!(
            *cell.read().expect("managed-settings cell poisoned"),
            Some(profile)
        );
    }

    #[tokio::test]
    async fn a_client_built_with_the_cell_reads_the_pushed_profile() {
        let host_handle = ManagedSettingsClient::new();
        let client = ClientBuilder::new()
            .with_managed_profile(host_handle.cell())
            .build();

        host_handle
            .update_profile(Some(profile_with(
                "environment.base",
                "\"https://vault.example.com\"",
            )))
            .await;

        assert_eq!(
            client
                .managed_settings()
                .get("environment.base".to_string()),
            Some("\"https://vault.example.com\"".to_string())
        );
    }

    #[test]
    fn a_client_built_without_a_cell_manages_nothing() {
        let client = ClientBuilder::new().build();

        assert_eq!(
            client
                .managed_settings()
                .get("environment.base".to_string()),
            None
        );
        assert_eq!(client.managed_settings().current_profile(), None);
    }

    #[tokio::test]
    async fn update_from_json_applies_the_flattened_settings() {
        let client = ManagedSettingsClient::new();

        client
            .update_from_json(Some(
                r#"{ "environment": { "base": "https://vault.example.com" } }"#.to_string(),
            ))
            .await
            .expect("an object is accepted");

        assert_eq!(
            client.get("environment.base".to_string()),
            Some("\"https://vault.example.com\"".to_string())
        );
    }

    #[tokio::test]
    async fn update_from_json_with_none_clears_the_profile() {
        let client = ManagedSettingsClient::new();
        client
            .update_profile(Some(profile_with("environment.base", "\"https://a\"")))
            .await;

        client
            .update_from_json(None)
            .await
            .expect("clearing is not an error");

        assert_eq!(client.current_profile(), None);
    }

    #[tokio::test]
    async fn update_from_json_clears_the_profile_and_errors_on_invalid_json() {
        let client = ManagedSettingsClient::new();
        client
            .update_profile(Some(profile_with("environment.base", "\"https://a\"")))
            .await;

        let error = client
            .update_from_json(Some("{ not json".to_string()))
            .await
            .expect_err("invalid JSON is rejected");

        assert!(matches!(error, ManagedSettingsError::InvalidJson(_)));
        assert_eq!(client.current_profile(), None);
    }

    #[tokio::test]
    async fn update_from_json_clears_the_profile_and_errors_on_a_non_object() {
        let client = ManagedSettingsClient::new();
        client
            .update_profile(Some(profile_with("environment.base", "\"https://a\"")))
            .await;

        let error = client
            .update_from_json(Some("[1, 2]".to_string()))
            .await
            .expect_err("an array is rejected");

        assert!(matches!(error, ManagedSettingsError::NotAnObject(_)));
        assert_eq!(client.current_profile(), None);
    }

    #[tokio::test]
    async fn an_update_signals_a_change_to_every_clone() {
        let client = ManagedSettingsClient::new();
        let mut changes = client.clone().changes();
        assert!(!changes.has_changed().expect("the sender is alive"));

        client
            .update_from_json(Some(r#"{ "a": 1 }"#.to_string()))
            .await
            .expect("an object is accepted");

        assert!(changes.has_changed().expect("the sender is alive"));
        changes.mark_unchanged();

        client
            .update_from_json(Some("not json".to_string()))
            .await
            .expect_err("invalid JSON is rejected");

        assert!(
            changes.has_changed().expect("the sender is alive"),
            "a rejected value clears the profile, which is a change"
        );
    }
}
