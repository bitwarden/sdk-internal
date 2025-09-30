use crate::{
    CoseKeyBytes, CoseSerializable, CryptoError, EncString, KeyEncryptable, KeyIds,
    KeyStoreContext, SignedPublicKey, SignedPublicKeyMessage, SpkiPublicKeyBytes,
    SymmetricCryptoKey,
};

/// Rotated set of account keys
pub struct RotatedUserKeys {
    /// The user's user key
    pub user_key: SymmetricCryptoKey,
    /// The verifying key
    pub verifying_key: CoseKeyBytes,
    /// Signing key, encrypted with a symmetric key (user key, org key)
    pub signing_key: EncString,
    /// The user's public key, signed by the signing key
    pub signed_public_key: SignedPublicKey,
    /// The user's public key, without signature
    pub public_key: SpkiPublicKeyBytes,
    /// The user's private key, encrypted with the user key
    pub private_key: EncString,
}

/// Generates a new user key and re-encrypts the current private and signing keys with it.
pub fn dangerous_get_v2_rotated_account_keys<Ids: KeyIds>(
    current_user_private_key_id: Ids::Asymmetric,
    current_user_signing_key_id: Ids::Signing,
    ctx: &KeyStoreContext<Ids>,
) -> Result<RotatedUserKeys, CryptoError> {
    let user_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();

    let current_private_key = ctx.get_asymmetric_key(current_user_private_key_id)?;
    let current_signing_key = ctx.get_signing_key(current_user_signing_key_id)?;

    let current_public_key = &current_private_key.to_public_key();
    let signed_public_key =
        SignedPublicKeyMessage::from_public_key(current_public_key)?.sign(current_signing_key)?;

    Ok(RotatedUserKeys {
        verifying_key: current_signing_key.to_verifying_key().to_cose(),
        signing_key: current_signing_key.to_cose().encrypt_with_key(&user_key)?,
        signed_public_key,
        public_key: current_public_key.to_der()?,
        private_key: current_private_key.to_der()?.encrypt_with_key(&user_key)?,
        user_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AsymmetricCryptoKey, KeyDecryptable, KeyStore, Pkcs8PrivateKeyBytes,
        PublicKeyEncryptionAlgorithm, SigningKey,
        traits::tests::{TestAsymmKey, TestIds, TestSigningKey, TestSymmKey},
    };

    #[test]
    fn test_account_key_rotation() {
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        // Generate a new user key
        let current_user_private_key_id = TestAsymmKey::A(0);
        let current_user_signing_key_id = TestSigningKey::A(0);

        // Make the keys
        ctx.generate_symmetric_key(TestSymmKey::A(0)).unwrap();
        ctx.make_signing_key(current_user_signing_key_id).unwrap();
        #[allow(deprecated)]
        ctx.set_asymmetric_key(
            current_user_private_key_id,
            AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1),
        )
        .unwrap();

        // Get the rotated account keys
        let rotated_keys = dangerous_get_v2_rotated_account_keys(
            current_user_private_key_id,
            current_user_signing_key_id,
            &ctx,
        )
        .unwrap();

        // Public/Private key
        assert_eq!(
            rotated_keys.public_key,
            ctx.get_asymmetric_key(current_user_private_key_id)
                .unwrap()
                .to_public_key()
                .to_der()
                .unwrap()
        );
        let decrypted_private_key: Vec<u8> = rotated_keys
            .private_key
            .decrypt_with_key(&rotated_keys.user_key)
            .unwrap();
        let private_key =
            AsymmetricCryptoKey::from_der(&Pkcs8PrivateKeyBytes::from(decrypted_private_key))
                .unwrap();
        assert_eq!(
            private_key.to_der().unwrap(),
            ctx.get_asymmetric_key(current_user_private_key_id)
                .unwrap()
                .to_der()
                .unwrap()
        );

        // Signing Key
        let decrypted_signing_key: Vec<u8> = rotated_keys
            .signing_key
            .decrypt_with_key(&rotated_keys.user_key)
            .unwrap();
        let signing_key =
            SigningKey::from_cose(&CoseKeyBytes::from(decrypted_signing_key)).unwrap();
        assert_eq!(
            signing_key.to_cose(),
            ctx.get_signing_key(current_user_signing_key_id)
                .unwrap()
                .to_cose(),
        );

        // Signed Public Key
        let signed_public_key = rotated_keys.signed_public_key;
        let unwrapped_key = signed_public_key
            .verify_and_unwrap(
                &ctx.get_signing_key(current_user_signing_key_id)
                    .unwrap()
                    .to_verifying_key(),
            )
            .unwrap();
        assert_eq!(
            unwrapped_key.to_der().unwrap(),
            ctx.get_asymmetric_key(current_user_private_key_id)
                .unwrap()
                .to_public_key()
                .to_der()
                .unwrap()
        );
    }
}
