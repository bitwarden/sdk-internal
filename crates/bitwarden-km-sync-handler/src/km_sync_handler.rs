//! Key management work that runs on every sync.

use bitwarden_core::{
    Client,
    key_management::{
        MasterPasswordUnlockData, V2UpgradeToken,
        account_cryptographic_state::WrappedAccountCryptographicState,
    },
};
use bitwarden_crypto::KeyId;
use bitwarden_user_crypto_management::UserCryptoManagementClientExt;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// The parts of a sync response the key management sync handler needs.
///
/// This is deliberately narrow rather than the full sync response: while the clients still own sync
/// they build their own response models, and marshalling those across the bindings boundary is not
/// worth it for a handful of fields.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct KmSyncData {
    /// The account's user decryption options, as the server reports them on sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub user_decryption: Option<KmSyncUserDecryption>,
    /// The account's cryptographic state, as the server reports it on sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub account_cryptographic_state: Option<WrappedAccountCryptographicState>,
}

/// The user decryption options a sync response carries, narrowed to the parts key management owns.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct KmSyncUserDecryption {
    /// Key id of the user key, as the server currently knows it. `None` means the server has no
    /// key id for this account and one should be reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub user_key_id: Option<KeyId>,
    /// Unlock data for accounts that have a master password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub master_password_unlock: Option<MasterPasswordUnlockData>,
    /// Token allowing unlock after a V1 to V2 upgrade, when one is outstanding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub v2_upgrade_token: Option<V2UpgradeToken>,
}

/// Runs the key management sync work for the given sync data.
///
/// Each concern gets its own handler below; add new ones here. Handlers share a signature so this
/// stays a flat list, and each is independent: none of them can fail the sync pass, and a handler
/// that gives up logs and leaves the rest to run. State is applied before any handler that talks to
/// the server, so a network failure never costs us a state write.
async fn handle_km_sync(client: &Client, data: &KmSyncData) {
    handle_user_decryption_options(client, data).await;
    handle_account_cryptographic_state(client, data).await;
    handle_user_key_id(client, data).await;

    // Further key management sync handlers go here.
}

/// Persists the user decryption options the server reported.
///
/// What the server reports replaces what is stored, so an option the server omits is cleared rather
/// than left behind: an absent V2 upgrade token means the upgrade is no longer outstanding, and
/// absent master password unlock data means the account has no master password.
async fn handle_user_decryption_options(client: &Client, data: &KmSyncData) {
    let Some(user_decryption) = data.user_decryption.as_ref() else {
        return;
    };

    let state_bridge = client.km_state_bridge();
    if !state_bridge.is_bridge_registered() {
        return;
    }

    match user_decryption.master_password_unlock.as_ref() {
        Some(master_password_unlock) => {
            state_bridge
                .set_masterpassword_unlock_data(master_password_unlock)
                .await;
            state_bridge.set_kdf(&master_password_unlock.kdf).await;
        }
        None => state_bridge.clear_masterpassword_unlock_data().await,
    }

    match user_decryption.v2_upgrade_token.as_ref() {
        Some(v2_upgrade_token) => state_bridge.set_v2_upgrade_token(v2_upgrade_token).await,
        None => state_bridge.clear_v2_upgrade_token().await,
    }
}

/// Persists the account cryptographic state the server reported.
async fn handle_account_cryptographic_state(client: &Client, data: &KmSyncData) {
    let Some(account_cryptographic_state) = data.account_cryptographic_state.as_ref() else {
        return;
    };

    let state_bridge = client.km_state_bridge();
    if !state_bridge.is_bridge_registered() {
        return;
    }

    state_bridge
        .set_account_cryptographic_state(account_cryptographic_state)
        .await;
}

/// Reports the current user key's key id to the server when the server does not already have one.
///
/// A no-op when the server already knows the key id, and when the client has no user key id to
/// report — either because the client is locked or because the user key carries no key id.
///
/// A failed report is logged and otherwise ignored: the backfill is opportunistic, and the next
/// sync will try again.
async fn handle_user_key_id(client: &Client, data: &KmSyncData) {
    let server_user_key_id = data
        .user_decryption
        .as_ref()
        .and_then(|d| d.user_key_id.as_ref());
    if server_user_key_id.is_some() {
        return;
    }

    info!("Server has no user key id; attempting to report the current one");
    match client.user_crypto_management().post_user_key_id().await {
        Ok(()) => {}
        // The client is locked, or the user key carries no key id. Neither is an error: there is
        // simply nothing to report.
        Err(
            bitwarden_user_crypto_management::PostUserKeyIdError::UserKeyNotAvailable
            | bitwarden_user_crypto_management::PostUserKeyIdError::NoKeyId,
        ) => {
            info!("No user key id available to report");
        }
        Err(e) => {
            // A rejection here is expected when another device won the race to backfill, so this is
            // reported as a warning rather than an error.
            warn!("Failed to report the user key id: {e:?}");
        }
    }
}

/// Client for the key management work that runs on every sync.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct KmSyncHandlerClient {
    client: Client,
}

impl KmSyncHandlerClient {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl KmSyncHandlerClient {
    /// Runs the key management sync work. Call this after each sync, once the user's cryptographic
    /// state has been applied.
    pub async fn on_sync(&self, data: KmSyncData) {
        handle_km_sync(&self.client, &data).await
    }
}

/// Extension trait to add the key management sync handler client to the main Bitwarden SDK client.
pub trait KmSyncHandlerClientExt {
    /// Get the key management sync handler client.
    fn km_sync_handler(&self) -> KmSyncHandlerClient;
}

impl KmSyncHandlerClientExt for Client {
    fn km_sync_handler(&self) -> KmSyncHandlerClient {
        KmSyncHandlerClient::new(self.clone())
    }
}

/// [`bitwarden_sync::SyncHandler`] implementation of the same work, reading the key id straight off
/// the generated sync response model.
///
/// Unused while the clients still own sync — they call [`KmSyncHandlerClient::on_sync`] instead —
/// but this is the entry point that survives once sync moves into the SDK.
///
/// Not available on `wasm32`: [`bitwarden_sync::SyncHandler`] requires `Send` futures, while the
/// generated `bitwarden-api-api` client is `?Send` on that target. `bitwarden-sync` is not exposed
/// to the wasm bindings either, so nothing is lost — wasm callers use
/// [`KmSyncHandlerClient::on_sync`].
#[cfg(not(target_arch = "wasm32"))]
pub struct KmSyncHandler {
    client: Client,
}

#[cfg(not(target_arch = "wasm32"))]
impl KmSyncHandler {
    /// Creates a handler bound to the given client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl bitwarden_sync::SyncHandler for KmSyncHandler {
    async fn on_sync(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), bitwarden_sync::SyncHandlerError> {
        let user_decryption = response.user_decryption.as_deref();

        let data = KmSyncData {
            user_decryption: user_decryption.map(|d| KmSyncUserDecryption {
                user_key_id: d
                    .user_key_id
                    .as_deref()
                    .and_then(|hex_encoded_key_id| hex_encoded_key_id.parse().ok()),
                // A response the SDK cannot parse is dropped rather than failing the whole sync;
                // the previously stored value stays put.
                master_password_unlock: d
                    .master_password_unlock
                    .as_deref()
                    .and_then(|m| MasterPasswordUnlockData::try_from(m).ok()),
                v2_upgrade_token: d
                    .v2_upgrade_token
                    .as_deref()
                    .and_then(|t| V2UpgradeToken::try_from(t).ok()),
            }),
            account_cryptographic_state: response
                .profile
                .as_deref()
                .and_then(|p| p.account_keys.as_deref())
                .and_then(|k| WrappedAccountCryptographicState::try_from(k).ok()),
        };
        handle_km_sync(&self.client, &data).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{SyncResponseModel, UserDecryptionResponseModel};
    use bitwarden_core::{
        Client,
        key_management::{KeySlotIds, SymmetricKeySlotId},
    };
    use bitwarden_crypto::{KeyStore, SymmetricKeyAlgorithm};
    #[cfg(not(target_arch = "wasm32"))]
    use bitwarden_sync::SyncHandler as _;

    use super::*;

    const KEY_ID_HEX: &str = "0123456789abcdef0123456789abcdef";

    /// A client whose key store holds a user key of the given algorithm, i.e. an unlocked client.
    fn unlocked_client(algorithm: SymmetricKeyAlgorithm) -> Client {
        let client = Client::new(None);
        let key_store: &KeyStore<KeySlotIds> = client.internal.get_key_store();
        let mut ctx = key_store.context_mut();
        let local = ctx.make_symmetric_key(algorithm);
        ctx.persist_symmetric_key(local, SymmetricKeySlotId::User)
            .expect("setting the user key should succeed");
        drop(ctx);
        client
    }

    #[tokio::test]
    async fn user_key_id_is_a_no_op_when_the_server_already_has_one() {
        let client = unlocked_client(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let data = KmSyncData {
            user_decryption: Some(KmSyncUserDecryption {
                user_key_id: Some(KEY_ID_HEX.parse().expect("valid key id")),
                ..Default::default()
            }),
            ..Default::default()
        };

        // No API client is configured on this bare client, so any attempt to reach the server
        // would fail rather than silently pass.
        handle_user_key_id(&client, &data).await;
    }

    #[tokio::test]
    async fn user_key_id_is_a_no_op_for_a_locked_client() {
        let client = Client::new(None);
        let data = KmSyncData::default();

        handle_user_key_id(&client, &data).await;
    }

    #[tokio::test]
    async fn user_key_id_is_a_no_op_when_the_user_key_carries_none() {
        let client = unlocked_client(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let data = KmSyncData::default();

        handle_user_key_id(&client, &data).await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn sync_handler_reads_the_key_id_off_the_user_decryption_data() {
        let client = unlocked_client(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let handler = KmSyncHandler {
            client: client.clone(),
        };

        // A response carrying the key id short-circuits, so this succeeds without any API access.
        let response = SyncResponseModel {
            user_decryption: Some(Box::new(UserDecryptionResponseModel {
                user_key_id: Some(KEY_ID_HEX.parse().expect("valid key id")),
                ..Default::default()
            })),
            ..Default::default()
        };

        handler
            .on_sync(&response)
            .await
            .expect("an already-known key id should short-circuit");
    }
}
