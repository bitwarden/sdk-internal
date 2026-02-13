//! The WASM sdk currently does not hold persistent SDK instances and instead re-createds SDK
//! instances frequently. The unlock-state is lost, since the user-key is only held in the SDK. This
//! file implements setting the user-key to WASM client-managed ephemeral state, so that
//! SDK-re-creations have access to the user-key.
//!
//! This is not required on UNIFFI since there SDK instances live as long as the client is unlocked.
//! Eventually, the WASM sdk will also hold SDK instances like described above.

use tracing::info;

use crate::{
    Client,
    key_management::{self, SymmetricKeyId},
};

/// Error indicating inability to set the user key into state
pub(crate) struct UnableToSetError;
/// Sets the decrypted user key into the client-managed state, so that it survives re-creation of
/// the SDK
pub(crate) async fn copy_user_key_to_client_managed_state(
    client: &Client,
) -> Result<(), UnableToSetError> {
    // The repository pattern requires us to specify a key. Here we use an empty string as the only
    // key for this repository map.
    const USER_KEY_REPOSITORY_KEY: &str = "";

    // Read the user-key from key-store. There should be no other reason to do this in other parts
    // of the SDK. Do not use this as an example.
    let user_key = {
        let key_store = client.internal.get_key_store();
        let ctx = key_store.context();
        #[expect(deprecated)]
        ctx.dangerous_get_symmetric_key(SymmetricKeyId::User)
            .map_err(|_| UnableToSetError)?
            .clone()
    };

    info!("Setting the user-key to client managed-state from SDK");
    // Set the user-key into the state repository.
    client
        .platform()
        .state()
        .get::<key_management::UserKeyState>()
        .map_err(|_| UnableToSetError)?
        .set(
            USER_KEY_REPOSITORY_KEY.to_string(),
            key_management::UserKeyState {
                decrypted_user_key: user_key.to_base64(),
            },
        )
        .await
        .map_err(|_| UnableToSetError)
}
