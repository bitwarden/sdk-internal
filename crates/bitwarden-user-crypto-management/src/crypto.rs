//! Functionality for re-encrypting account cryptographic state during user key rotation.
use bitwarden_core::{
    UserId,
    key_management::{
        KeyIds, SymmetricKeyId, account_cryptographic_state::WrappedAccountCryptographicState,
    },
};
use tracing::debug;

/// Rotates an account cryptographic state and upgrades it to V2 if necessary.
/// This function fails and logs an error via tracing if the passed keys are invalid, or if the
/// account cryptographic state is malformed.
#[allow(unused)]
pub(super) fn rotate_account_cryptographic_state(
    wrapped_account_cryptographic_state: &WrappedAccountCryptographicState,
    current_user_key_id: &SymmetricKeyId,
    new_user_key_id: &SymmetricKeyId,
    user_id: UserId,
    ctx: &mut bitwarden_crypto::KeyStoreContext<KeyIds>,
) -> Result<bitwarden_api_api::models::AccountKeysRequestModel, ()> {
    debug!(
        "Rotating account cryptographic state for user_id={} from key_id={:?} to key_id={:?}",
        user_id, current_user_key_id, new_user_key_id
    );

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

    debug!(
        "Converting rotated account cryptographic state to request model for user_id={}",
        user_id
    );
    // Rotate the account keys for the user
    let account_keys_model = rotated_account_cryptographic_state
        .to_request_model(new_user_key_id, ctx)
        .map_err(|_| ())?;
    Ok(account_keys_model)
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
    use bitwarden_crypto::{
        KeyStore, PublicKey, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm,
    };
    use bitwarden_encoding::B64;

    use super::*;

    /// Creates a V1 wrapped state for testing. This mimics what make_v1 does in bitwarden-core,
    /// but is accessible from this crate.
    fn make_v1_wrapped_state(
        ctx: &mut bitwarden_crypto::KeyStoreContext<KeyIds>,
    ) -> (SymmetricKeyId, PublicKey, WrappedAccountCryptographicState) {
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapped_private_key = ctx.wrap_private_key(user_key, private_key).unwrap();

        (
            user_key,
            ctx.get_public_key(private_key).unwrap(),
            WrappedAccountCryptographicState::V1 {
                private_key: wrapped_private_key,
            },
        )
    }

    #[test]
    fn test_rotate_v1_to_v2_returns_account_keys_model() {
        // Create a key store and context
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        // Create a V1-style wrapped state
        let user_id = UserId::new_v4();
        let (old_user_key_id, public_key, wrapped_state) = make_v1_wrapped_state(&mut ctx);

        // Create a new user key for rotation
        let new_user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let model = rotate_account_cryptographic_state(
            &wrapped_state,
            &old_user_key_id,
            &new_user_key_id,
            user_id,
            &mut ctx,
        )
        .expect("rotate_account_cryptographic_state should succeed");

        let actual_public_key: B64 = public_key.to_der().unwrap().into();
        let model_public_key = model
            .public_key_encryption_key_pair
            .expect("public_key_encryption_key_pair should be present")
            .public_key
            .expect("public_key should be present");
        assert_eq!(
            actual_public_key.to_string(),
            model_public_key,
            "Public key should be correctly included in the model"
        );
    }

    #[test]
    fn test_rotate_v2_to_v2_returns_account_keys_model() {
        // Create a key store and context
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        // Create a V2-style wrapped state
        let user_id = UserId::new_v4();
        let (old_user_key_id, wrapped_state) =
            WrappedAccountCryptographicState::make(&mut ctx, user_id).unwrap();

        // Get the public key before rotation
        let private_key_id = match &wrapped_state {
            WrappedAccountCryptographicState::V2 { private_key, .. } => ctx
                .unwrap_private_key(old_user_key_id, private_key)
                .unwrap(),
            _ => panic!("Expected V2 state"),
        };
        let public_key = ctx.get_public_key(private_key_id).unwrap();

        // Create a new user key for rotation
        let new_user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let model = rotate_account_cryptographic_state(
            &wrapped_state,
            &old_user_key_id,
            &new_user_key_id,
            user_id,
            &mut ctx,
        )
        .expect("rotate_account_cryptographic_state should succeed");

        let actual_public_key: B64 = public_key.to_der().unwrap().into();
        let public_key_encryption_key_pair = model
            .public_key_encryption_key_pair
            .as_ref()
            .expect("public_key_encryption_key_pair should be present");
        let model_public_key = public_key_encryption_key_pair
            .public_key
            .as_ref()
            .expect("public_key should be present");
        assert_eq!(
            actual_public_key.to_string(),
            *model_public_key,
            "Public key should be correctly included in the model"
        );

        // Assert signed_public_key is present
        assert!(
            public_key_encryption_key_pair.signed_public_key.is_some(),
            "signed_public_key should be present for V2 state"
        );

        // Note: The actual cryptographic correctness of these values (signatures, key material)
        // is verified in the account_cryptographic_state tests. This test only asserts that
        // the conversion to AccountKeysRequestModel is reasonable (i.e., expected fields are
        // present).

        // Assert signature_key_pair (verifying key) is present
        let signature_key_pair = model
            .signature_key_pair
            .as_ref()
            .expect("signature_key_pair should be present for V2 state");
        assert!(
            signature_key_pair.verifying_key.is_some(),
            "verifying_key should be present"
        );
        assert!(
            signature_key_pair.wrapped_signing_key.is_some(),
            "wrapped_signing_key should be present"
        );
        assert!(
            signature_key_pair.signature_algorithm.is_some(),
            "signature_algorithm should be present"
        );

        // Assert security_state is present
        let security_state = model
            .security_state
            .as_ref()
            .expect("security_state should be present for V2 state");
        assert!(
            security_state.security_state.is_some(),
            "security_state content should be present"
        );
    }
}
