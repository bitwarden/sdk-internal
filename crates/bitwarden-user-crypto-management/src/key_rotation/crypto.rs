//! Functionality for re-encrypting account cryptographic state during user key rotation.
use bitwarden_core::{
    UserId,
    key_management::{
        KeyIds, SymmetricKeyId, account_cryptographic_state::WrappedAccountCryptographicState,
    },
};

/// Rotates an account cryptographic state and upgrades it to V2 if necessary.
/// This function fails and logs an error via tracing if the passed keys are invalid, or if the
/// account cryptographic state is malformed.
pub(super) fn rotate_account_cryptographic_state(
    wrapped_account_cryptographic_state: &WrappedAccountCryptographicState,
    current_user_key_id: &SymmetricKeyId,
    new_user_key_id: &SymmetricKeyId,
    user_id: UserId,
    ctx: &mut bitwarden_crypto::KeyStoreContext<KeyIds>,
) -> Result<bitwarden_api_api::models::AccountKeysRequestModel, ()> {
    // We can't really handle the error variants here. Either the provided account cryptographic
    // state is broken, or a key is missing.
    let rotated_account_cryptographic_state = WrappedAccountCryptographicState::rotate(
        wrapped_account_cryptographic_state,
        current_user_key_id,
        new_user_key_id,
        user_id,
        ctx,
    )
    .map_err(|_| ())?;
    // Rotate the account keys for the user
    let account_keys_model = rotated_account_cryptographic_state
        .to_request_model(new_user_key_id, ctx)
        .map_err(|_| ())?;
    Ok(account_keys_model)
}
