//! Replication of one [`ManagedSettingsClient`]'s profile to a client in another process over
//! `bitwarden-ipc`.
//!
//! The client that acquires the profile mirrors to a single destination: it answers the
//! destination's [`ManagedProfileRequest`] and sends a [`ManagedProfilePush`] after every update.
//! The mirror subscribes to pushes from its authority and requests the current profile once, so a
//! mirror that starts after the authority acquired a profile still receives it.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bitwarden_ipc::{
    Endpoint, IpcClient, IpcClientExt, PayloadTypeName, RpcHandler, RpcRequest, RpcRequestInfo,
    SubscribeError, TypedIncomingMessage, TypedReceiveError,
};
use bitwarden_managed_settings_types::ManagementProfile;
use bitwarden_threading::{
    spawn,
    time::{sleep, timeout},
};
use serde::{Deserialize, Serialize};

use crate::ManagedSettingsClient;

/// How long a mirror waits for the response to its profile request. The authority answers from
/// memory, so only an authority that never registered its handler, or a transport that never
/// delivers, takes this long.
const PROFILE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Sent by the mirroring client to its destination on every profile update.
#[derive(Serialize, Deserialize)]
pub(crate) struct ManagedProfilePush {
    pub(crate) profile: Option<ManagementProfile>,
}

impl PayloadTypeName for ManagedProfilePush {
    const PAYLOAD_TYPE_NAME: &'static str = "managed-settings.profile-push";
}

/// Sent by a mirror to request the current profile, for example after it starts or reloads.
#[derive(Serialize, Deserialize)]
pub(crate) struct ManagedProfileRequest;

impl RpcRequest for ManagedProfileRequest {
    type Response = Result<Option<ManagementProfile>, ManagedProfileRequestError>;
    const NAME: &str = "ManagedSettingsProfileRequest";
}

/// Returned to a peer that is not the mirroring client's destination.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum ManagedProfileRequestError {
    NotDestination,
}

/// Answers a mirror's request from the shared profile cell, for the destination only.
pub(crate) struct ManagedProfileRequestHandler {
    pub(crate) client: ManagedSettingsClient,
    pub(crate) destination: Endpoint,
}

impl RpcHandler for ManagedProfileRequestHandler {
    type Request = ManagedProfileRequest;

    async fn handle(
        &self,
        _: Self::Request,
        info: RpcRequestInfo,
    ) -> Result<Option<ManagementProfile>, ManagedProfileRequestError> {
        // Native-messaging peers reach the same IPC client, so the profile is only returned to
        // the destination.
        if info.source.to_endpoint() != self.destination {
            tracing::warn!(source = ?info.source, "Refused a managed profile request");
            return Err(ManagedProfileRequestError::NotDestination);
        }
        Ok(self.client.current_profile())
    }
}

/// The peer a mirroring client pushes its updates to.
pub(crate) struct MirrorDestination {
    pub(crate) ipc_client: Arc<dyn IpcClient>,
    pub(crate) endpoint: Endpoint,
}

/// Mirror-side state shared by the push receive loop and the one-off profile request.
struct MirrorProgress {
    /// Set once a push has been applied. A request response is applied only while this is unset,
    /// because a push always carries the newest profile when it is sent.
    push_applied: Mutex<bool>,
}

/// Subscribes `client` to pushes from `authority`, then requests the current profile once in the
/// background. Returns once subscribed.
pub(crate) async fn mirror_from(
    client: ManagedSettingsClient,
    ipc_client: Arc<dyn IpcClient>,
    authority: Endpoint,
) -> Result<(), SubscribeError> {
    let mut subscription = ipc_client.subscribe_typed::<ManagedProfilePush>().await?;
    let progress = Arc::new(MirrorProgress {
        push_applied: Mutex::new(false),
    });

    let receive_client = client.clone();
    let receive_progress = progress.clone();
    let receive_authority = authority.clone();
    spawn(async move {
        loop {
            match subscription.receive(None).await {
                Ok(message) => apply_push(
                    &receive_client,
                    &receive_progress,
                    &receive_authority,
                    message,
                ),
                // The channel reports closed while the transport reconnects. Waiting keeps this
                // loop from spinning on the event loop in the meantime.
                Err(TypedReceiveError::Channel(
                    tokio::sync::broadcast::error::RecvError::Closed,
                )) => {
                    tracing::info!("Managed profile mirror channel closed, waiting for it to open");
                    sleep(Duration::from_secs(1)).await;
                }
                Err(error) => {
                    tracing::warn!(?error, "Failed to receive a managed profile push");
                }
            }
        }
    });

    spawn(async move {
        request_current_profile(&client, &progress, ipc_client.as_ref(), authority).await;
    });

    Ok(())
}

fn apply_push(
    client: &ManagedSettingsClient,
    progress: &MirrorProgress,
    authority: &Endpoint,
    message: TypedIncomingMessage<ManagedProfilePush>,
) {
    if message.source.to_endpoint() != *authority {
        tracing::warn!(source = ?message.source, "Rejected a managed profile push from a peer that is not the authority");
        return;
    }

    let mut push_applied = progress
        .push_applied
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tracing::info!("Applying a pushed managed profile");
    client.apply(message.payload.profile);
    *push_applied = true;
}

/// Requests the authority's current profile once. A failure is logged and not retried, because the
/// authority registers its handler before the mirror starts, and every later update arrives as a
/// push.
///
/// [`IpcClientExt::request`] does not report which peer sent the response, so its source is not
/// checked here. The response arrives on a topic named after a random request id, which travels
/// encrypted to the authority only, so another peer has no way to learn the topic.
async fn request_current_profile(
    client: &ManagedSettingsClient,
    progress: &MirrorProgress,
    ipc_client: &dyn IpcClient,
    authority: Endpoint,
) {
    // The timeout wraps the whole request rather than only the wait for the response, because
    // sending can also wait on the peer, for example to complete a session handshake.
    let response = timeout(
        PROFILE_REQUEST_TIMEOUT,
        ipc_client.request(ManagedProfileRequest, authority.clone(), None),
    )
    .await;

    let profile = match response {
        Ok(Ok(Ok(profile))) => profile,
        Ok(Ok(Err(ManagedProfileRequestError::NotDestination))) => {
            tracing::warn!(
                ?authority,
                "The authority refused the managed profile request because this client is not its destination"
            );
            return;
        }
        Ok(Err(error)) => {
            tracing::warn!(?authority, ?error, "Managed profile request failed");
            return;
        }
        Err(_) => {
            tracing::warn!(
                ?authority,
                timeout = ?PROFILE_REQUEST_TIMEOUT,
                "Managed profile request timed out"
            );
            return;
        }
    };

    let push_applied = progress
        .push_applied
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *push_applied {
        tracing::info!(
            "Dropped a managed profile response because a newer push was already applied"
        );
        return;
    }
    tracing::info!("Applying the requested managed profile");
    client.apply(profile);
}
