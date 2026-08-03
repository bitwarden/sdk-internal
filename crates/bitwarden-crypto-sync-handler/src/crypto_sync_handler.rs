//! Key management work that runs on every sync.

#[cfg(not(target_arch = "wasm32"))]
use bitwarden_core::key_management::{
    MasterPasswordError, V2UpgradeTokenError, WebAuthnPrfError,
    account_cryptographic_state::AccountKeysResponseParseError,
};
use bitwarden_core::{
    Client,
    key_management::{
        MasterPasswordUnlockData, V2UpgradeToken, WebAuthnPrfUnlockData, WebAuthnPrfUnlockOption,
        account_cryptographic_state::WrappedAccountCryptographicState,
        state_bridge::StateBridgeClient,
    },
};
use bitwarden_crypto::KeyId;
use bitwarden_user_crypto_management::UserCryptoManagementClientExt;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
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
    /// The WebAuthn PRF credentials the account can unlock with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub web_authn_prf_options: Option<Vec<WebAuthnPrfUnlockOption>>,
}

/// Errors returned when a sync response cannot be converted into [`CryptoSyncData`].
///
/// The conversion happens before anything is written to state, so returning one of these leaves
/// state untouched rather than partially updated.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, thiserror::Error)]
pub enum CryptoSyncDataParseError {
    /// The sync response carried master password unlock data that could not be parsed.
    #[error("Sync response carried unparseable master password unlock data")]
    MasterPasswordUnlock(#[source] MasterPasswordError),
    /// The sync response carried a V2 upgrade token that could not be parsed.
    #[error("Sync response carried an unparseable V2 upgrade token")]
    V2UpgradeToken(#[source] V2UpgradeTokenError),
    /// The sync response carried a WebAuthn PRF unlock option that could not be parsed.
    #[error("Sync response carried an unparseable WebAuthn PRF unlock option")]
    WebAuthnPrfOption(#[source] WebAuthnPrfError),
    /// The sync response carried account cryptographic state that could not be parsed.
    #[error("Sync response carried unparseable account cryptographic state")]
    AccountCryptographicState(#[source] AccountKeysResponseParseError),
}

#[cfg(not(target_arch = "wasm32"))]
impl TryFrom<&bitwarden_api_api::models::SyncResponseModel> for CryptoSyncData {
    type Error = CryptoSyncDataParseError;

    fn try_from(
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            user_decryption: response
                .user_decryption
                .as_deref()
                .map(CryptoSyncUserDecryption::try_from)
                .transpose()?,
            account_cryptographic_state: response
                .profile
                .as_deref()
                .and_then(|p| p.account_keys.as_deref())
                .map(WrappedAccountCryptographicState::try_from)
                .transpose()
                .map_err(CryptoSyncDataParseError::AccountCryptographicState)?,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TryFrom<&bitwarden_api_api::models::UserDecryptionResponseModel> for CryptoSyncUserDecryption {
    type Error = CryptoSyncDataParseError;

    fn try_from(
        response: &bitwarden_api_api::models::UserDecryptionResponseModel,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            master_password_unlock: response
                .master_password_unlock
                .as_deref()
                .map(MasterPasswordUnlockData::try_from)
                .transpose()
                .map_err(CryptoSyncDataParseError::MasterPasswordUnlock)?,
            v2_upgrade_token: response
                .v2_upgrade_token
                .as_deref()
                .map(V2UpgradeToken::try_from)
                .transpose()
                .map_err(CryptoSyncDataParseError::V2UpgradeToken)?,
            web_authn_prf_options: response
                .web_authn_prf_options
                .as_deref()
                .map(|options| {
                    options
                        .iter()
                        .map(WebAuthnPrfUnlockOption::try_from)
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(CryptoSyncDataParseError::WebAuthnPrfOption)?,
        })
    }
}

/// Runs the key management sync work for the given sync data.
async fn set_crypto_sync_to_state(client: &Client, data: &CryptoSyncData) {
    if !client.km_state_bridge().is_bridge_registered() {
        info!("Key management state bridge not registered; skipping sync work");
        return;
    }

    let state_bridge = client.km_state_bridge();
    // Handlers MUST NOT fail, to avoid partial state writes
    handle_user_decryption_options(&state_bridge, data).await;
    handle_account_cryptographic_state(&state_bridge, data).await;
}

/// Persists the user decryption options the server reported.
async fn handle_user_decryption_options(state_bridge: &StateBridgeClient, data: &CryptoSyncData) {
    let Some(user_decryption) = data.user_decryption.as_ref() else {
        return;
    };

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

    // An absent list and an empty list both mean the account has no PRF-capable credentials.
    match user_decryption.web_authn_prf_options.as_ref() {
        Some(options) if !options.is_empty() => {
            state_bridge
                .set_webauthn_prf_unlock_data(&WebAuthnPrfUnlockData {
                    options: options.clone(),
                })
                .await
        }
        _ => state_bridge.clear_webauthn_prf_unlock_data().await,
    }
}

/// Persists the account cryptographic state the server reported.
async fn handle_account_cryptographic_state(
    state_bridge: &StateBridgeClient,
    data: &CryptoSyncData,
) {
    if let Some(account_cryptographic_state) = data.account_cryptographic_state.as_ref() {
        state_bridge
            .set_account_cryptographic_state(account_cryptographic_state)
            .await;
    } else {
        state_bridge.clear_account_cryptographic_state().await;
    }
}

/// Reports the current user key's key id to the server when the server does not already have one.
async fn handle_user_key_id(client: &Client, data: &CryptoSyncData) {
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

async fn run_crypto_sync_hooks(client: &Client, data: &CryptoSyncData) {
    handle_user_key_id(client, data).await;
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
        set_crypto_sync_to_state(&self.client, &data).await
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
        // Parsing happens up front so that a malformed response fails the sync without having
        // written any state.
        let data = CryptoSyncData::try_from(response)?;

        set_crypto_sync_to_state(&self.client, &data).await;
        run_crypto_sync_hooks(&self.client, &data).await;
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use bitwarden_api_api::models::{
        KdfType, MasterPasswordUnlockKdfResponseModel, MasterPasswordUnlockResponseModel,
        SyncResponseModel, UserDecryptionResponseModel, WebAuthnPrfDecryptionOption,
    };

    use super::*;

    const TEST_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";
    const TEST_SALT: &str = "test@example.com";

    fn master_password_unlock(
        master_key_encrypted_user_key: Option<String>,
    ) -> MasterPasswordUnlockResponseModel {
        MasterPasswordUnlockResponseModel {
            kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                kdf_type: KdfType::PBKDF2_SHA256,
                iterations: 600_000,
                memory: None,
                parallelism: None,
            }),
            master_key_encrypted_user_key,
            salt: Some(TEST_SALT.to_string()),
        }
    }

    fn sync_response(user_decryption: UserDecryptionResponseModel) -> SyncResponseModel {
        SyncResponseModel {
            user_decryption: Some(Box::new(user_decryption)),
            ..Default::default()
        }
    }

    #[test]
    fn test_try_from_empty_response_is_empty_data() {
        let data = CryptoSyncData::try_from(&SyncResponseModel::default()).unwrap();

        assert!(data.user_decryption.is_none());
        assert!(data.account_cryptographic_state.is_none());
    }

    #[test]
    fn test_try_from_valid_master_password_unlock_succeeds() {
        let response = sync_response(UserDecryptionResponseModel {
            master_password_unlock: Some(Box::new(master_password_unlock(Some(
                TEST_USER_KEY.to_string(),
            )))),
            ..Default::default()
        });

        let data = CryptoSyncData::try_from(&response).unwrap();

        let user_decryption = data.user_decryption.unwrap();
        assert_eq!(
            user_decryption.master_password_unlock.unwrap().salt,
            TEST_SALT
        );
    }

    #[test]
    fn test_try_from_malformed_master_password_unlock_errors() {
        // Missing wrapped user key.
        let response = sync_response(UserDecryptionResponseModel {
            master_password_unlock: Some(Box::new(master_password_unlock(None))),
            ..Default::default()
        });

        assert!(matches!(
            CryptoSyncData::try_from(&response),
            Err(CryptoSyncDataParseError::MasterPasswordUnlock(_))
        ));
    }

    #[test]
    fn test_try_from_malformed_webauthn_prf_option_errors() {
        let response = sync_response(UserDecryptionResponseModel {
            web_authn_prf_options: Some(vec![WebAuthnPrfDecryptionOption::default()]),
            ..Default::default()
        });

        assert!(matches!(
            CryptoSyncData::try_from(&response),
            Err(CryptoSyncDataParseError::WebAuthnPrfOption(_))
        ));
    }
}
