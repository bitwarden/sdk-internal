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
use thiserror::Error;
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
    let Some(incoming) = data.account_cryptographic_state.as_ref() else {
        return;
    };

    // We need to prevent the server from downgrading a V2 user to V1 or a V2 user with state
    // version X to state version Y < X. To do this, we check the incoming state against the
    // local state.
    if let Some(existing) = state_bridge.get_account_cryptographic_state().await {
        let result = downgrade_prevention(&existing, incoming);

        if let Err(e) = result {
            warn!(
                error = ?e,
                "Refusing to persist the synced account cryptographic state; keeping the local one"
            );
            return;
        }
    }

    state_bridge.set_account_cryptographic_state(incoming).await;
}

/// Reasons an incoming account cryptographic state is rejected in favour of the local one.
#[derive(Debug, Error)]
enum DowngradePreventionError {
    /// The account is V2 locally, but the incoming state is V1, i.e. the signed security state was
    /// dropped entirely.
    #[error(
        "The incoming state is V1 while the local state is V2; the signed security state was omitted"
    )]
    SecurityStateOmitted,
    /// The incoming state is signed by a different signing key than the local one.
    #[error("The verifying key of the incoming state differs from the local one")]
    VerifyingKeyChanged,
    /// A signed security state is not signed by the account's verifying key.
    #[error("The {0} signed security state is not signed by the account's verifying key")]
    SecurityStateSignatureFailed(&'static str),
    /// The incoming security state version is lower than the local one.
    #[error("The security state version was downgraded from {local} to {incoming}")]
    SecurityVersionDowngraded {
        /// The version of the locally known security state.
        local: u64,
        /// The version of the incoming security state.
        incoming: u64,
    },
}

/// Checks that the incoming account cryptographic state is not a downgrade of the state that is
/// already known locally.
///
/// A malicious or compromised server can hand out any account cryptographic state it likes, so an
/// incoming state is only accepted if it is at least as strong as the local one:
///
/// - A V2 account must stay V2 — an incoming V1 state would silently drop the signed security
///   state, which is exactly the downgrade the security state exists to prevent.
/// - The verifying key must not change, so the server cannot swap in a signing key pair of its own
///   and sign a weaker security state with it.
/// - Both the local and the incoming signed security state must verify under that verifying key.
/// - The security state version must not decrease.
///
/// A state that cannot be checked at all — no verifying key to derive it from and none carried
/// along — is treated as a rejection: an unverifiable state is never persisted over one that was
/// verified.
///
/// Please note, the verifying key being mismatched with the signing key is at latest detected when
/// setting to context. It cannot be done here because the encryption keys may not be available if
/// sync happens while locked.
///
/// Upgrades (V1 to V2) and unchanged V1 accounts have no security state to protect and are always
/// accepted.
fn downgrade_prevention(
    local: &WrappedAccountCryptographicState,
    incoming: &WrappedAccountCryptographicState,
) -> Result<(), DowngradePreventionError> {
    let WrappedAccountCryptographicState::V2 {
        signing_key: _,
        security_state: local_security_state,
        verifying_key: local_verifying_key,
        ..
    } = local
    else {
        // A V1 account carries no security state, so neither staying on V1 nor upgrading to V2 can
        // be a downgrade.
        return Ok(());
    };

    let WrappedAccountCryptographicState::V2 {
        signing_key: _,
        security_state: incoming_security_state,
        verifying_key: incoming_verifying_key,
        ..
    } = incoming
    else {
        tracing::warn!("WARNING!!! The server attempted a security downgrade!");
        return Err(DowngradePreventionError::SecurityStateOmitted);
    };

    if local_verifying_key != incoming_verifying_key {
        return Err(DowngradePreventionError::VerifyingKeyChanged);
    }

    if let (Some(local_verifying_key), Some(incoming_verifying_key)) =
        (local_verifying_key, incoming_verifying_key)
    {
        let local_version = local_security_state
            .to_owned()
            .verify_and_unwrap(local_verifying_key)
            .map_err(|_| DowngradePreventionError::SecurityStateSignatureFailed("local"))?
            .version();
        let incoming_version = incoming_security_state
            .to_owned()
            .verify_and_unwrap(incoming_verifying_key)
            .map_err(|_| DowngradePreventionError::SecurityStateSignatureFailed("incoming"))?
            .version();
        if incoming_version < local_version {
            return Err(DowngradePreventionError::SecurityVersionDowngraded {
                local: local_version,
                incoming: incoming_version,
            });
        }
    }

    Ok(())
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
    use bitwarden_api_api::models::{SyncResponseModel, UserDecryptionResponseModel};
    use bitwarden_core::key_management::{
        KeySlotIds, SecurityState, SymmetricKeySlotId,
        state_bridge::test_support::InMemoryStateBridge,
    };
    use bitwarden_crypto::{
        KeyStore, PublicKeyEncryptionAlgorithm, SignatureAlgorithm, SymmetricKeyAlgorithm,
        VerifyingKey,
    };
    #[cfg(not(target_arch = "wasm32"))]
    use bitwarden_sync::SyncHandler as _;

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

    /// A client with an in-memory state bridge registered, and no keys in its key store.
    fn client_with_bridge() -> Client {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        client
    }

    /// Creates a fresh V2 state and unlocks the client with the user key protecting it.
    fn make_v2_state(client: &Client) -> WrappedAccountCryptographicState {
        let mut ctx = client.internal.get_key_store().context_mut();
        let (user_key, state) =
            WrappedAccountCryptographicState::make(&mut ctx).expect("making a V2 state succeeds");
        ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
            .expect("setting the user key should succeed");
        state
    }

    /// Creates a V1 state and unlocks the client with the user key protecting it.
    fn make_v1_state(client: &Client) -> WrappedAccountCryptographicState {
        let mut ctx = client.internal.get_key_store().context_mut();
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let state = WrappedAccountCryptographicState::V1 {
            private_key: ctx
                .wrap_private_key(user_key, private_key)
                .expect("wrapping the private key succeeds"),
        };
        ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
            .expect("setting the user key should succeed");
        state
    }

    /// A `SecurityState` of an arbitrary version. The version is private and only ever set to the
    /// current one in code, so tests go through deserialization to reach other versions.
    fn security_state_with_version(version: u64) -> SecurityState {
        serde_json::from_value(serde_json::json!({ "version": version }))
            .expect("a security state deserializes from its version")
    }

    /// Copies the state, replacing the signed security state with one of the given version, signed
    /// by the state's own signing key.
    fn with_security_version(
        client: &Client,
        state: &WrappedAccountCryptographicState,
        version: u64,
    ) -> WrappedAccountCryptographicState {
        let WrappedAccountCryptographicState::V2 {
            private_key,
            signed_public_key,
            signing_key,
            ..
        } = state
        else {
            panic!("expected a V2 state");
        };

        let mut ctx = client.internal.get_key_store().context_mut();
        let signing_key_id = ctx
            .unwrap_signing_key(SymmetricKeySlotId::User, signing_key)
            .expect("the signing key unwraps with the user key");
        let security_state = security_state_with_version(version)
            .sign(signing_key_id, &mut ctx)
            .expect("signing the security state succeeds");

        WrappedAccountCryptographicState::V2 {
            private_key: private_key.clone(),
            signed_public_key: signed_public_key.clone(),
            signing_key: signing_key.clone(),
            security_state,
            verifying_key: Some(
                ctx.get_verifying_key(signing_key_id)
                    .expect("the signing key is in the context"),
            ),
        }
    }

    /// Copies the state, replacing the signing key (and therefore the verifying key) with a freshly
    /// generated one, wrapped by the same user key.
    fn with_new_signing_key(
        client: &Client,
        state: &WrappedAccountCryptographicState,
    ) -> WrappedAccountCryptographicState {
        let WrappedAccountCryptographicState::V2 {
            private_key,
            signed_public_key,
            ..
        } = state
        else {
            panic!("expected a V2 state");
        };

        let mut ctx = client.internal.get_key_store().context_mut();
        let signing_key_id = ctx.make_signing_key(SignatureAlgorithm::MlDsa44);
        let security_state = SecurityState::new()
            .sign(signing_key_id, &mut ctx)
            .expect("signing the security state succeeds");

        WrappedAccountCryptographicState::V2 {
            private_key: private_key.clone(),
            signed_public_key: signed_public_key.clone(),
            signing_key: ctx
                .wrap_signing_key(SymmetricKeySlotId::User, signing_key_id)
                .expect("wrapping the signing key succeeds"),
            security_state,
            verifying_key: Some(
                ctx.get_verifying_key(signing_key_id)
                    .expect("the signing key is in the context"),
            ),
        }
    }

    /// Copies the state without the verifying key, as states stored before the field existed.
    fn without_verifying_key(
        state: &WrappedAccountCryptographicState,
    ) -> WrappedAccountCryptographicState {
        replace_verifying_key(state, None)
    }

    /// Copies `state`, claiming the verifying key of `other`.
    fn with_verifying_key_of(
        state: &WrappedAccountCryptographicState,
        other: &WrappedAccountCryptographicState,
    ) -> WrappedAccountCryptographicState {
        let WrappedAccountCryptographicState::V2 { verifying_key, .. } = other else {
            panic!("expected a V2 state");
        };
        replace_verifying_key(state, verifying_key.clone())
    }

    fn replace_verifying_key(
        state: &WrappedAccountCryptographicState,
        verifying_key: Option<VerifyingKey>,
    ) -> WrappedAccountCryptographicState {
        let WrappedAccountCryptographicState::V2 {
            private_key,
            signed_public_key,
            signing_key,
            security_state,
            ..
        } = state
        else {
            panic!("expected a V2 state");
        };

        WrappedAccountCryptographicState::V2 {
            private_key: private_key.clone(),
            signed_public_key: signed_public_key.clone(),
            signing_key: signing_key.clone(),
            security_state: security_state.clone(),
            verifying_key,
        }
    }

    /// Runs the handler for the given incoming state and returns what the bridge holds afterwards.
    async fn sync_account_cryptographic_state(
        client: &Client,
        incoming: &WrappedAccountCryptographicState,
    ) -> Option<WrappedAccountCryptographicState> {
        let state_bridge = client.km_state_bridge();
        let data = CryptoSyncData {
            account_cryptographic_state: Some(incoming.clone()),
            ..Default::default()
        };
        handle_account_cryptographic_state(&state_bridge, &data).await;
        client
            .km_state_bridge()
            .get_account_cryptographic_state()
            .await
    }

    #[tokio::test]
    async fn account_cryptographic_state_is_persisted_when_there_is_no_local_state() {
        let client = client_with_bridge();
        let incoming = make_v2_state(&client);

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&incoming));
    }

    #[tokio::test]
    async fn account_cryptographic_state_is_persisted_when_unchanged() {
        let client = client_with_bridge();
        let state = make_v2_state(&client);
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&state)
            .await;

        let stored = sync_account_cryptographic_state(&client, &state).await;

        assert_eq!(stored.as_ref(), Some(&state));
    }

    #[tokio::test]
    async fn account_cryptographic_state_upgrade_from_v1_to_v2_is_persisted() {
        let client = client_with_bridge();
        let local = make_v1_state(&client);
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;
        // The V2 state replaces the user key in the store, which is what an upgrade does.
        let incoming = make_v2_state(&client);

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&incoming));
    }

    #[tokio::test]
    async fn account_cryptographic_state_downgrade_from_v2_to_v1_is_rejected() {
        let client = client_with_bridge();
        let local = make_v2_state(&client);
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;
        let incoming = WrappedAccountCryptographicState::V1 {
            private_key: match &local {
                WrappedAccountCryptographicState::V2 { private_key, .. } => private_key.clone(),
                _ => unreachable!("the local state is V2"),
            },
        };

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&local));
    }

    #[tokio::test]
    async fn account_cryptographic_state_with_a_changed_verifying_key_is_rejected() {
        let client = client_with_bridge();
        let local = make_v2_state(&client);
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;
        let incoming = with_new_signing_key(&client, &local);

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&local));
    }

    #[tokio::test]
    async fn account_cryptographic_state_with_a_lower_security_version_is_rejected() {
        let client = client_with_bridge();
        let state = make_v2_state(&client);
        let local = with_security_version(&client, &state, 3);
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;
        let incoming = with_security_version(&client, &state, 2);

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&local));
    }

    #[tokio::test]
    async fn account_cryptographic_state_with_a_higher_security_version_is_persisted() {
        let client = client_with_bridge();
        let local = make_v2_state(&client);
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;
        let incoming = with_security_version(&client, &local, 3);

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&incoming));
    }

    #[tokio::test]
    async fn account_cryptographic_state_is_checked_against_the_carried_verifying_key_when_locked()
    {
        // The states are built in a throwaway client, so the syncing client stays locked and only
        // the verifying keys carried along with the states are available.
        let key_source = Client::new(None);
        let local = make_v2_state(&key_source);
        let incoming = with_security_version(&key_source, &local, 3);

        let client = client_with_bridge();
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&incoming));
    }

    #[tokio::test]
    async fn account_cryptographic_state_downgrade_is_caught_when_locked() {
        let key_source = Client::new(None);
        let state = make_v2_state(&key_source);
        let local = with_security_version(&key_source, &state, 3);
        let incoming = with_security_version(&key_source, &state, 2);

        let client = client_with_bridge();
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&local));
    }

    #[tokio::test]
    async fn account_cryptographic_state_with_a_verifying_key_that_does_not_match_is_rejected() {
        let client = client_with_bridge();
        let local = make_v2_state(&client);
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;
        // The signing key is the account's own, but the claimed verifying key is someone else's.
        let foreign = make_v2_state(&Client::new(None));
        let incoming = with_verifying_key_of(&local, &foreign);

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&local));
    }

    #[tokio::test]
    async fn account_cryptographic_state_of_another_account_is_rejected() {
        let client = client_with_bridge();
        let local = make_v2_state(&client);
        client
            .km_state_bridge()
            .set_account_cryptographic_state(&local)
            .await;
        // Wrapped by a different user key, and signed by a different signing key.
        let incoming = make_v2_state(&Client::new(None));

        let stored = sync_account_cryptographic_state(&client, &incoming).await;

        assert_eq!(stored.as_ref(), Some(&local));
    }
}
