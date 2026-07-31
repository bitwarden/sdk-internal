//! Key management work that runs on every sync.

use bitwarden_core::{
    Client,
    key_management::{
        MasterPasswordUnlockData, V2UpgradeToken,
        account_cryptographic_state::WrappedAccountCryptographicState,
    },
};
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use tracing::warn;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// The parts of a sync response the key management sync handler needs.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct CryptoSyncData {
    /// The account's user decryption options, as the server reports them on sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub user_decryption: Option<CryptoSyncUserDecryption>,
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
pub struct CryptoSyncUserDecryption {
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
async fn handle_crypto_sync(client: &Client, data: &CryptoSyncData) {
    // Handlers MUST NOT fail, to avoid partial state writes
    handle_user_decryption_options(client, data).await;
    handle_account_cryptographic_state(client, data).await;

    // Further key management sync handlers go here.
}

/// Persists the user decryption options the server reported.
async fn handle_user_decryption_options(client: &Client, data: &CryptoSyncData) {
    let Some(user_decryption) = data.user_decryption.as_ref() else {
        return;
    };

    // This is necessary until all clients implement the state bridge.
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
async fn handle_account_cryptographic_state(client: &Client, data: &CryptoSyncData) {
    let Some(account_cryptographic_state) = data.account_cryptographic_state.as_ref() else {
        return;
    };

    // This is necessary until all clients implement the state bridge.
    let state_bridge = client.km_state_bridge();
    if !state_bridge.is_bridge_registered() {
        return;
    }

    state_bridge
        .set_account_cryptographic_state(account_cryptographic_state)
        .await;
}

/// Client for the key management work that runs on every sync.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CryptoSyncHandlerClient {
    client: Client,
}

impl CryptoSyncHandlerClient {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl CryptoSyncHandlerClient {
    /// Runs the key management sync work. Call this after each sync, once the user's cryptographic
    /// state has been applied.
    pub async fn on_sync(&self, data: CryptoSyncData) {
        handle_crypto_sync(&self.client, &data).await
    }
}

/// Extension trait to add the key management sync handler client to the main Bitwarden SDK client.
pub trait CryptoSyncHandlerClientExt {
    /// Get the key management sync handler client.
    fn crypto_sync_handler(&self) -> CryptoSyncHandlerClient;
}

impl CryptoSyncHandlerClientExt for Client {
    fn crypto_sync_handler(&self) -> CryptoSyncHandlerClient {
        CryptoSyncHandlerClient::new(self.clone())
    }
}

/// [`bitwarden_sync::SyncHandler`] implementation of the same work, reading the key id straight off
/// the generated sync response model.
///
/// Unused while the clients still own sync — they call [`CryptoSyncHandlerClient::on_sync`] instead
/// — but this is the entry point that survives once sync moves into the SDK.
///
/// Not available on `wasm32`: [`bitwarden_sync::SyncHandler`] requires `Send` futures, while the
/// generated `bitwarden-api-api` client is `?Send` on that target. `bitwarden-sync` is not exposed
/// to the wasm bindings either, so nothing is lost — wasm callers use
/// [`CryptoSyncHandlerClient::on_sync`].
#[cfg(not(target_arch = "wasm32"))]
pub struct CryptoSyncHandler {
    client: Client,
}

#[cfg(not(target_arch = "wasm32"))]
impl CryptoSyncHandler {
    /// Creates a handler bound to the given client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl bitwarden_sync::SyncHandler for CryptoSyncHandler {
    async fn on_sync(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), bitwarden_sync::SyncHandlerError> {
        let user_decryption = response.user_decryption.as_deref();

        let data = CryptoSyncData {
            user_decryption: user_decryption.map(|d| CryptoSyncUserDecryption {
                master_password_unlock: d.master_password_unlock.as_deref().and_then(|m| {
                    MasterPasswordUnlockData::try_from(m)
                        .inspect_err(|e| {
                            warn!(error = ?e, "Sync response carried unparseable master password unlock data; treating it as absent")
                        })
                        .ok()
                }),
                v2_upgrade_token: d.v2_upgrade_token.as_deref().and_then(|t| {
                    V2UpgradeToken::try_from(t)
                        .inspect_err(|e| {
                            warn!(error = ?e, "Sync response carried an unparseable V2 upgrade token; treating it as absent")
                        })
                        .ok()
                }),
            }),
            account_cryptographic_state: response
                .profile
                .as_deref()
                .and_then(|p| p.account_keys.as_deref())
                .and_then(|k| {
                    WrappedAccountCryptographicState::try_from(k)
                        .inspect_err(|e| {
                            warn!(error = ?e, "Sync response carried unparseable account cryptographic state; ignoring it")
                        })
                        .ok()
                }),
        };
        handle_crypto_sync(&self.client, &data).await;
        Ok(())
    }
}
