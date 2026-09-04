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
    },
};
use bitwarden_crypto::KeyId;
use serde::{Deserialize, Serialize};
use tracing::warn;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// The parts of a sync response the key management sync handler needs.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
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
#[bitwarden_ffi::wasm_record]
pub struct CryptoSyncUserDecryption {
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
    /// The id of the account's current user key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub user_key_id: Option<KeyId>,
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
    /// The sync response carried a user key id that could not be parsed.
    #[error("Sync response carried an unparseable user key id")]
    UserKeyId(#[source] bitwarden_crypto::CryptoError),
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
            user_key_id: response
                .user_key_id
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(CryptoSyncDataParseError::UserKeyId)?,
        })
    }
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
            state_bridge
                .set_kdf_config(&master_password_unlock.kdf)
                .await;
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

    // The stored key id mirrors the server's. An absent one means the server has no id recorded for
    // this user key, so a previously stored id no longer describes anything and is dropped.
    match user_decryption.user_key_id.as_ref() {
        Some(user_key_id) => state_bridge.set_user_key_id(user_key_id).await,
        None => state_bridge.clear_user_key_id().await,
    }
}

/// Persists the account cryptographic state the server reported.
async fn handle_account_cryptographic_state(client: &Client, data: &CryptoSyncData) {
    let Some(incoming) = data.account_cryptographic_state.as_ref() else {
        return;
    };

    // This is necessary until all clients implement the state bridge.
    let state_bridge = client.km_state_bridge();
    if !state_bridge.is_bridge_registered() {
        return;
    }

    // A malicious or compromised server must not be able to move an account back to V1, which
    // would silently drop the signed security state that V2 exists to protect.
    if let Some(local) = state_bridge.get_account_cryptographic_state().await
        && is_v2_to_v1_downgrade(&local, incoming)
    {
        warn!("Refusing a V2 to V1 account cryptographic state downgrade; keeping the local state");
        return;
    }

    state_bridge.set_account_cryptographic_state(incoming).await;
}

/// Whether the incoming state moves a locally V2 account back to V1.
///
/// V1 accounts carry no security state, so staying on V1 or upgrading to V2 is never a downgrade.
fn is_v2_to_v1_downgrade(
    local: &WrappedAccountCryptographicState,
    incoming: &WrappedAccountCryptographicState,
) -> bool {
    matches!(local, WrappedAccountCryptographicState::V2 { .. })
        && matches!(incoming, WrappedAccountCryptographicState::V1 { .. })
}

/// Client for the key management work that runs on every sync.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[bitwarden_ffi::wasm_object]
pub struct CryptoSyncHandlerClient {
    client: Client,
}

impl CryptoSyncHandlerClient {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

#[bitwarden_ffi::wasm_export]
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

/// [`bitwarden_sync::SyncHandler`] implementation of the same work, reading the sync data straight
/// off the generated sync response model.
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

        handle_crypto_sync(&self.client, &data).await;
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use bitwarden_api_api::models::{
        KdfType, MasterPasswordUnlockKdfResponseModel, MasterPasswordUnlockResponseModel,
        SyncResponseModel, UserDecryptionResponseModel, WebAuthnPrfDecryptionOption,
    };
    use bitwarden_core::key_management::{
        KeySlotIds, state_bridge::test_support::InMemoryStateBridge,
    };
    use bitwarden_crypto::{KeyStore, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm};

    use super::*;

    const TEST_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";
    const TEST_SALT: &str = "test@example.com";
    const TEST_USER_KEY_ID: &str = "000102030405060708090a0b0c0d0e0f";

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
            contained_key_id: None,
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

    #[test]
    fn test_try_from_valid_user_key_id_succeeds() {
        let response = sync_response(UserDecryptionResponseModel {
            user_key_id: Some(TEST_USER_KEY_ID.to_string()),
            ..Default::default()
        });

        let data = CryptoSyncData::try_from(&response).unwrap();

        let user_key_id = data.user_decryption.unwrap().user_key_id.unwrap();
        assert_eq!(user_key_id.to_string(), TEST_USER_KEY_ID);
    }

    #[test]
    fn test_try_from_absent_user_key_id_is_none() {
        // The account has other unlock data, but the server has no key id recorded for it yet.
        let response = sync_response(UserDecryptionResponseModel {
            master_password_unlock: Some(Box::new(master_password_unlock(Some(
                TEST_USER_KEY.to_string(),
            )))),
            ..Default::default()
        });

        let data = CryptoSyncData::try_from(&response).unwrap();

        assert!(data.user_decryption.unwrap().user_key_id.is_none());
    }

    #[test]
    fn test_try_from_malformed_user_key_id_errors() {
        for malformed in [
            "not hex at all",
            // Valid hex, but not 16 bytes worth.
            "00ff",
            // Odd number of hex digits.
            "000102030405060708090a0b0c0d0e0",
        ] {
            let response = sync_response(UserDecryptionResponseModel {
                user_key_id: Some(malformed.to_string()),
                ..Default::default()
            });

            assert!(
                matches!(
                    CryptoSyncData::try_from(&response),
                    Err(CryptoSyncDataParseError::UserKeyId(_))
                ),
                "{malformed:?} should not parse as a key id"
            );
        }
    }

    /// The key id has to reach the state bridge, not just the parsed data. An absent id clears a
    /// previously stored one.
    #[tokio::test]
    async fn test_handle_crypto_sync_writes_and_clears_user_key_id() {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));

        let with_key_id = CryptoSyncData::try_from(&sync_response(UserDecryptionResponseModel {
            user_key_id: Some(TEST_USER_KEY_ID.to_string()),
            ..Default::default()
        }))
        .unwrap();
        handle_crypto_sync(&client, &with_key_id).await;

        let stored = client.km_state_bridge().get_user_key_id().await.unwrap();
        assert_eq!(stored.to_string(), TEST_USER_KEY_ID);

        let without_key_id =
            CryptoSyncData::try_from(&sync_response(UserDecryptionResponseModel::default()))
                .unwrap();
        handle_crypto_sync(&client, &without_key_id).await;

        assert!(client.km_state_bridge().get_user_key_id().await.is_none());
    }

    /// A client with an in-memory state bridge registered.
    fn client_with_bridge() -> Client {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        client
    }

    fn make_v2_state() -> WrappedAccountCryptographicState {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (_, state) =
            WrappedAccountCryptographicState::make(&mut ctx).expect("making a V2 state succeeds");
        state
    }

    fn make_v1_state() -> WrappedAccountCryptographicState {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);

        WrappedAccountCryptographicState::V1 {
            private_key: ctx
                .wrap_private_key(user_key, private_key)
                .expect("wrapping the private key succeeds"),
        }
    }

    /// Runs the handler for the given incoming state and returns what the bridge holds afterwards.
    async fn sync_account_cryptographic_state(
        client: &Client,
        incoming: &WrappedAccountCryptographicState,
    ) -> Option<WrappedAccountCryptographicState> {
        let data = CryptoSyncData {
            account_cryptographic_state: Some(incoming.clone()),
            ..Default::default()
        };
        handle_account_cryptographic_state(client, &data).await;
        client
            .km_state_bridge()
            .get_account_cryptographic_state()
            .await
    }

    #[tokio::test]
    async fn test_account_cryptographic_state_is_persisted_when_there_is_no_local_state() {
        let client = client_with_bridge();
        let incoming = make_v2_state();

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&incoming));
    }

    #[tokio::test]
    async fn test_account_cryptographic_state_upgrade_from_v1_to_v2_is_persisted() {
        let client = client_with_bridge();
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&make_v1_state())
            .await;
        let incoming = make_v2_state();

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&incoming));
    }

    #[tokio::test]
    async fn test_account_cryptographic_state_downgrade_from_v2_to_v1_is_rejected() {
        let client = client_with_bridge();
        let local = make_v2_state();
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;

        let stored = sync_account_cryptographic_state(&client, &make_v1_state()).await;

        assert_eq!(stored.as_ref(), Some(&local));
    }
}
