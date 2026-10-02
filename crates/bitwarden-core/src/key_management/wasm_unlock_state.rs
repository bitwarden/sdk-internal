//! The WASM sdk currently does not hold persistent SDK instances and instead re-createds SDK
//! instances frequently. The unlock-state is lost, since the user-key is only held in the SDK. This
//! file implements setting the user-key into the KM state bridge, so that SDK-re-creations have
//! access to the user-key.
//!
//! This is not required on UNIFFI since there SDK instances live as long as the client is unlocked.
//! Eventually, the WASM sdk will also hold SDK instances like described above.

use bitwarden_crypto::SymmetricCryptoKey;
use tracing::info;

use crate::{Client, key_management::SymmetricKeySlotId};

/// Error indicating inability to set the user key into state
pub(crate) struct UnableToSetError;
/// Sets the decrypted user key into the KM state bridge, so that it survives re-creation of
/// the SDK
pub(crate) async fn copy_user_key_to_state(client: &Client) -> Result<(), UnableToSetError> {
    // Read the user-key from key-store. There should be no other reason to do this in other parts
    // of the SDK. Do not use this as an example.
    let user_key = {
        let key_store = client.internal.get_key_store();
        let ctx = key_store.context();
        #[expect(deprecated)]
        ctx.dangerous_get_symmetric_key(SymmetricKeySlotId::User)
            .map_err(|_| UnableToSetError)?
            .clone()
    };

    let bridge = client.km_state_bridge();
    if !bridge.is_bridge_registered() {
        // No state bridge registered, older clients should just return gracefully.
        info!("No state bridge registered, exiting gracefully");
        return Ok(());
    }

    // We do not want to set the user-key if it is already set as that may trigger an observable
    // loop in the client side which subscribes to the state
    if let Some(existing_key) = bridge.get_user_key().await {
        if existing_key == user_key {
            info!("User-key in state bridge is already up to date, skipping set");
            return Ok(());
        }
        info!("User-key in state bridge is outdated, updating it");
    } else {
        info!("No user-key in state bridge, setting it");
    }

    info!("Setting the user-key to the state bridge from SDK");
    bridge.set_user_key(&user_key).await;
    Ok(())
}

pub(crate) struct UnableToGetError;
pub(crate) async fn get_user_key_from_state(
    client: &Client,
) -> Result<SymmetricCryptoKey, UnableToGetError> {
    info!("Getting the user-key from the state bridge in SDK");
    client
        .km_state_bridge()
        .get_user_key()
        .await
        .ok_or(UnableToGetError)
}
