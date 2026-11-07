//! Trusts the current device for trusted device encryption (TDE).
//!
//! ```text
//!  user key (KeyStore) ──▶ DeviceKey::trust_device ──▶ PUT /devices/{identifier}/keys
//!                                   │
//!                                   └─ device key ──▶ state bridge (host storage)
//! ```
//!
//! The user picks whether to trust the device before decryption. The choice is persisted and
//! acted on once the user key is available, see [`DeviceTrustClient::trust_device_if_required`].
//!
//! Unlocking with a trusted device combines the stored device key with the wrapped keys the
//! server returns at login, see [`TrustedDeviceOption`].

use bitwarden_api_api::{apis::ApiClient, models::DeviceKeysRequestModel};
use bitwarden_crypto::{DeviceKey, EncString, SymmetricCryptoKey, UnsignedSharedKey};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{Client, key_management::SymmetricKeySlotId};

/// The user's choice whether to trust this device, made before decryption.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_record]
pub enum TrustDeviceChoice {
    /// Trust the device once the user key is available.
    Trust,
    /// Do not trust the device.
    DontTrust,
}

/// Result of [`DeviceTrustClient::trust_device_if_required`].
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_record]
pub enum TrustOutcome {
    /// The device was trusted.
    Trusted,
    /// The user did not choose to trust the device. Nothing changed.
    NotRequested,
}

/// The trusted device keys the server returns with the login response, as received.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct TrustedDeviceOption {
    /// The device private key, wrapped by the device key.
    pub encrypted_private_key: Option<EncString>,
    /// The user key, encapsulated to the device public key.
    pub encrypted_user_key: Option<UnsignedSharedKey>,
}

/// Why a trusted device could not unlock.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeviceUnlockError {
    /// No device key is stored: the device is not trusted.
    NotTrusted,
    /// A device key is stored but the server sent no keys. Reported to the server.
    TrustLost,
    /// The stored device key does not unwrap the server's keys. The key was removed.
    KeyInvalid,
}

/// Recovers the user key from the stored device key and the server's trusted device keys.
///
/// Mirrors the clients' behavior: a device key without server keys is reported as lost trust, and
/// a device key that fails to unwrap is deleted so the device stops claiming trust.
pub(crate) async fn unlock_user_key(
    client: &Client,
    api_client: &ApiClient,
    option: TrustedDeviceOption,
) -> Result<SymmetricCryptoKey, DeviceUnlockError> {
    let bridge = client.km_state_bridge();
    if !bridge.is_bridge_registered() {
        return Err(DeviceUnlockError::NotTrusted);
    }

    let Some(device_key) = bridge.get_device_key().await else {
        return Err(DeviceUnlockError::NotTrusted);
    };

    let (Some(private_key), Some(user_key)) =
        (option.encrypted_private_key, option.encrypted_user_key)
    else {
        if let Err(e) = api_client.devices_api().post_lost_trust().await {
            tracing::warn!("Failed to report lost device trust: {e:?}");
        }
        return Err(DeviceUnlockError::TrustLost);
    };

    let device_key: DeviceKey = device_key
        .to_base64()
        .to_string()
        .try_into()
        .map_err(|_| DeviceUnlockError::KeyInvalid)?;
    match device_key.decrypt_user_key(private_key, user_key) {
        Ok(user_key) => Ok(user_key),
        Err(_) => {
            tracing::error!("Failed to decrypt using device key. Removing device key.");
            bridge.clear_device_key().await;
            Err(DeviceUnlockError::KeyInvalid)
        }
    }
}

/// Errors from trusting a device.
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum DeviceTrustError {
    /// The user key is not in the key store.
    #[error("The vault is locked")]
    Locked,
    /// The client was built without a device identifier.
    #[error("No device identifier is configured")]
    MissingDeviceIdentifier,
    /// No state bridge is registered to persist the device key.
    #[error("The key-management state bridge is not registered")]
    StateBridgeNotRegistered,
    /// Generating or wrapping the device keys failed.
    #[error("Failed to create device keys")]
    Crypto,
    /// The server rejected the device keys.
    #[error("Failed to post device keys")]
    Api,
}

/// Trusts the current device for trusted device encryption.
#[derive(Clone)]
#[bitwarden_ffi::wasm_object]
pub struct DeviceTrustClient {
    pub(crate) client: Client,
}

impl Client {
    /// Trusted device encryption operations.
    pub fn device_trust(&self) -> DeviceTrustClient {
        DeviceTrustClient {
            client: self.clone(),
        }
    }
}

#[bitwarden_ffi::wasm_export]
impl DeviceTrustClient {
    /// Trusts this device: creates device keys from the user key, posts them to the server, and
    /// persists the device key.
    pub async fn trust_device(&self) -> Result<(), DeviceTrustError> {
        let config = self.client.internal.get_api_configurations();
        trust_device(&self.client, &config.api_client).await
    }

    /// Trusts this device if the user chose to, then clears the choice.
    pub async fn trust_device_if_required(&self) -> Result<TrustOutcome, DeviceTrustError> {
        let config = self.client.internal.get_api_configurations();
        trust_device_if_required(&self.client, &config.api_client).await
    }

    /// Persists the user's choice whether to trust this device.
    pub async fn set_trust_device_choice(
        &self,
        choice: TrustDeviceChoice,
    ) -> Result<(), DeviceTrustError> {
        let bridge = self.client.km_state_bridge();
        if !bridge.is_bridge_registered() {
            return Err(DeviceTrustError::StateBridgeNotRegistered);
        }

        bridge
            .set_should_trust_device(&(choice == TrustDeviceChoice::Trust))
            .await;
        Ok(())
    }
}

async fn trust_device_if_required(
    client: &Client,
    api_client: &ApiClient,
) -> Result<TrustOutcome, DeviceTrustError> {
    let bridge = client.km_state_bridge();
    if !bridge.is_bridge_registered() {
        return Err(DeviceTrustError::StateBridgeNotRegistered);
    }

    // The choice is single-use: absent or false means there is nothing to do.
    if bridge.get_should_trust_device().await != Some(true) {
        return Ok(TrustOutcome::NotRequested);
    }

    trust_device(client, api_client).await?;
    bridge.clear_should_trust_device().await;
    Ok(TrustOutcome::Trusted)
}

pub(crate) async fn trust_device(
    client: &Client,
    api_client: &ApiClient,
) -> Result<(), DeviceTrustError> {
    let bridge = client.km_state_bridge();
    if !bridge.is_bridge_registered() {
        return Err(DeviceTrustError::StateBridgeNotRegistered);
    }

    let device_identifier = client
        .internal
        .device_identifier
        .clone()
        .ok_or(DeviceTrustError::MissingDeviceIdentifier)?;

    // Create the device keys from the user key held in the key store.
    let keys = {
        let key_store = client.internal.get_key_store();
        let ctx = key_store.context();
        // FIXME: [PM-18099] Once DeviceKey deals with KeySlotIds, this should be updated
        #[allow(deprecated)]
        let user_key = ctx
            .dangerous_get_symmetric_key(SymmetricKeySlotId::User)
            .map_err(|_| DeviceTrustError::Locked)?;
        DeviceKey::trust_device(user_key).map_err(|_| DeviceTrustError::Crypto)?
    };

    info!("Posting trusted device keys");
    api_client
        .devices_api()
        .put_keys(
            device_identifier.as_str(),
            Some(DeviceKeysRequestModel {
                encrypted_user_key: keys.protected_user_key.to_string(),
                encrypted_public_key: keys.protected_device_public_key.to_string(),
                encrypted_private_key: keys.protected_device_private_key.to_string(),
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to post trusted device keys: {e:?}");
            DeviceTrustError::Api
        })?;

    // Persist only after the server accepted the keys, so a failed post leaves no orphan key.
    let device_key =
        SymmetricCryptoKey::try_from(keys.device_key).map_err(|_| DeviceTrustError::Crypto)?;
    bridge.set_device_key(&device_key).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::DeviceResponseModel;
    use bitwarden_crypto::{EncString, SymmetricKeyAlgorithm, UnsignedSharedKey};

    use super::*;
    use crate::{ClientSettings, key_management::state_bridge::test_support::InMemoryStateBridge};

    const DEVICE_IDENTIFIER: &str = "test-device-id";

    fn device_response() -> DeviceResponseModel {
        DeviceResponseModel {
            object: None,
            id: None,
            name: None,
            r#type: None,
            identifier: None,
            creation_date: None,
            last_activity_date: None,
            is_trusted: None,
            encrypted_user_key: None,
            encrypted_public_key: None,
        }
    }

    fn client(device_identifier: Option<&str>) -> Client {
        Client::new(Some(ClientSettings {
            device_identifier: device_identifier.map(String::from),
            ..Default::default()
        }))
    }

    fn with_bridge(client: Client) -> Client {
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        client
    }

    fn with_user_key(client: Client) -> Client {
        {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
                .expect("persisting user key should succeed");
        }
        client
    }

    fn trusted_client() -> Client {
        with_user_key(with_bridge(client(Some(DEVICE_IDENTIFIER))))
    }

    fn api_accepting_keys(times: usize) -> ApiClient {
        ApiClient::new_mocked(move |mock| {
            mock.devices_api
                .expect_put_keys()
                .times(times)
                .returning(|identifier, body| {
                    assert_eq!(identifier, DEVICE_IDENTIFIER);
                    assert!(body.is_some());
                    Ok(device_response())
                });
        })
    }

    fn api_rejecting_keys() -> ApiClient {
        ApiClient::new_mocked(|mock| {
            mock.devices_api.expect_put_keys().once().returning(|_, _| {
                Err(serde_json::Error::io(std::io::Error::other("API error")).into())
            });
        })
    }

    #[tokio::test]
    async fn trust_device_posts_keys_that_unwrap_to_the_user_key() {
        let client = trusted_client();
        let posted = std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured = posted.clone();
        let api = ApiClient::new_mocked(move |mock| {
            mock.devices_api
                .expect_put_keys()
                .once()
                .returning(move |_, body| {
                    *captured.lock().unwrap() = body;
                    Ok(device_response())
                });
        });

        trust_device(&client, &api).await.unwrap();

        // The stored device key must unwrap the posted keys back to the current user key.
        let body = posted.lock().unwrap().take().expect("keys were posted");
        let device_key: DeviceKey = client
            .km_state_bridge()
            .get_device_key()
            .await
            .expect("device key is stored")
            .to_base64()
            .to_string()
            .try_into()
            .unwrap();
        let decrypted = device_key
            .decrypt_user_key(
                body.encrypted_private_key.parse::<EncString>().unwrap(),
                body.encrypted_user_key
                    .parse::<UnsignedSharedKey>()
                    .unwrap(),
            )
            .unwrap();

        #[allow(deprecated)]
        let user_key: SymmetricCryptoKey = client
            .internal
            .get_key_store()
            .context()
            .dangerous_get_symmetric_key(SymmetricKeySlotId::User)
            .unwrap()
            .clone();
        assert_eq!(decrypted, user_key);
    }

    #[tokio::test]
    async fn trust_device_fails_when_locked() {
        let client = with_bridge(client(Some(DEVICE_IDENTIFIER)));

        let result = trust_device(&client, &api_accepting_keys(0)).await;

        assert!(matches!(result, Err(DeviceTrustError::Locked)));
        assert!(client.km_state_bridge().get_device_key().await.is_none());
    }

    #[tokio::test]
    async fn trust_device_fails_without_device_identifier() {
        let client = with_user_key(with_bridge(client(None)));

        let result = trust_device(&client, &api_accepting_keys(0)).await;

        assert!(matches!(
            result,
            Err(DeviceTrustError::MissingDeviceIdentifier)
        ));
    }

    #[tokio::test]
    async fn trust_device_fails_without_state_bridge() {
        let client = with_user_key(client(Some(DEVICE_IDENTIFIER)));

        let result = trust_device(&client, &api_accepting_keys(0)).await;

        assert!(matches!(
            result,
            Err(DeviceTrustError::StateBridgeNotRegistered)
        ));
    }

    #[tokio::test]
    async fn trust_device_keeps_no_device_key_when_post_fails() {
        let client = trusted_client();

        let result = trust_device(&client, &api_rejecting_keys()).await;

        assert!(matches!(result, Err(DeviceTrustError::Api)));
        assert!(client.km_state_bridge().get_device_key().await.is_none());
    }

    #[tokio::test]
    async fn trust_device_if_required_trusts_and_clears_choice() {
        let client = trusted_client();
        client
            .device_trust()
            .set_trust_device_choice(TrustDeviceChoice::Trust)
            .await
            .unwrap();

        let outcome = trust_device_if_required(&client, &api_accepting_keys(1))
            .await
            .unwrap();

        assert_eq!(outcome, TrustOutcome::Trusted);
        assert!(client.km_state_bridge().get_device_key().await.is_some());
        assert!(
            client
                .km_state_bridge()
                .get_should_trust_device()
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn trust_device_if_required_skips_when_user_declined() {
        let client = trusted_client();
        client
            .device_trust()
            .set_trust_device_choice(TrustDeviceChoice::DontTrust)
            .await
            .unwrap();

        let outcome = trust_device_if_required(&client, &api_accepting_keys(0))
            .await
            .unwrap();

        assert_eq!(outcome, TrustOutcome::NotRequested);
        assert!(client.km_state_bridge().get_device_key().await.is_none());
    }

    #[tokio::test]
    async fn trust_device_if_required_skips_when_no_choice() {
        let client = trusted_client();

        let outcome = trust_device_if_required(&client, &api_accepting_keys(0))
            .await
            .unwrap();

        assert_eq!(outcome, TrustOutcome::NotRequested);
    }

    #[tokio::test]
    async fn trust_device_if_required_keeps_choice_when_trust_fails() {
        let client = trusted_client();
        client
            .device_trust()
            .set_trust_device_choice(TrustDeviceChoice::Trust)
            .await
            .unwrap();

        let result = trust_device_if_required(&client, &api_rejecting_keys()).await;

        assert!(matches!(result, Err(DeviceTrustError::Api)));
        assert_eq!(
            client.km_state_bridge().get_should_trust_device().await,
            Some(true)
        );
    }

    /// Trusts `client` and returns the keys the server would send back at login.
    async fn trust_and_capture(client: &Client) -> TrustedDeviceOption {
        let posted = std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured = posted.clone();
        let api = ApiClient::new_mocked(move |mock| {
            mock.devices_api
                .expect_put_keys()
                .once()
                .returning(move |_, body| {
                    *captured.lock().unwrap() = body;
                    Ok(device_response())
                });
        });
        trust_device(client, &api).await.unwrap();

        let body = posted.lock().unwrap().take().unwrap();
        TrustedDeviceOption {
            encrypted_private_key: Some(body.encrypted_private_key.parse().unwrap()),
            encrypted_user_key: Some(body.encrypted_user_key.parse().unwrap()),
        }
    }

    fn api_expecting_lost_trust(times: usize) -> ApiClient {
        ApiClient::new_mocked(move |mock| {
            mock.devices_api
                .expect_post_lost_trust()
                .times(times)
                .returning(|| Ok(()));
        })
    }

    #[tokio::test]
    async fn unlock_user_key_recovers_the_user_key() {
        let client = trusted_client();
        let option = trust_and_capture(&client).await;

        let user_key = unlock_user_key(&client, &api_expecting_lost_trust(0), option)
            .await
            .unwrap();

        #[allow(deprecated)]
        let expected = client
            .internal
            .get_key_store()
            .context()
            .dangerous_get_symmetric_key(SymmetricKeySlotId::User)
            .unwrap()
            .clone();
        assert_eq!(user_key, expected);
    }

    #[tokio::test]
    async fn unlock_user_key_fails_without_device_key() {
        let client = trusted_client();
        let option = TrustedDeviceOption {
            encrypted_private_key: None,
            encrypted_user_key: None,
        };

        let result = unlock_user_key(&client, &api_expecting_lost_trust(0), option).await;

        assert_eq!(result.unwrap_err(), DeviceUnlockError::NotTrusted);
    }

    #[tokio::test]
    async fn unlock_user_key_reports_lost_trust_when_server_sends_no_keys() {
        let client = trusted_client();
        trust_and_capture(&client).await;
        let option = TrustedDeviceOption {
            encrypted_private_key: None,
            encrypted_user_key: None,
        };

        let result = unlock_user_key(&client, &api_expecting_lost_trust(1), option).await;

        assert_eq!(result.unwrap_err(), DeviceUnlockError::TrustLost);
        assert!(client.km_state_bridge().get_device_key().await.is_some());
    }

    #[tokio::test]
    async fn unlock_user_key_removes_a_device_key_that_does_not_unwrap() {
        let client = trusted_client();
        let option = trust_and_capture(&client).await;
        // A different device key, as if this device's key was replaced.
        client
            .km_state_bridge()
            .set_device_key(&SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            ))
            .await;

        let result = unlock_user_key(&client, &api_expecting_lost_trust(0), option).await;

        assert_eq!(result.unwrap_err(), DeviceUnlockError::KeyInvalid);
        assert!(client.km_state_bridge().get_device_key().await.is_none());
    }

    #[tokio::test]
    async fn set_trust_device_choice_fails_without_state_bridge() {
        let client = client(Some(DEVICE_IDENTIFIER));

        let result = client
            .device_trust()
            .set_trust_device_choice(TrustDeviceChoice::Trust)
            .await;

        assert!(matches!(
            result,
            Err(DeviceTrustError::StateBridgeNotRegistered)
        ));
    }
}
