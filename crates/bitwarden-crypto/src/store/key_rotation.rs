use serde::{Deserialize, Serialize};

use crate::{
    AsymmetricCryptoKey, AsymmetricPublicCryptoKey, CoseKeyBytes, CoseSerializable, CryptoError,
    EncString, KeyDecryptable, KeyEncryptable, KeyIds, KeyStoreContext, Pkcs8PrivateKeyBytes,
    SignedPublicKey, SignedPublicKeyMessage, SpkiPublicKeyBytes, SymmetricCryptoKey,
    UnsignedSharedKey,
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

/// A set of keys where a given `DownstreamKey` is protected by an encrypted public/private
/// key-pair. The `DownstreamKey` is used to encrypt/decrypt data, while the public/private key-pair
/// is used to rotate the `DownstreamKey`.
///
/// The `PrivateKey` is protected by an `UpstreamKey`, such as a `DeviceKey`, or `PrfKey`,
/// and the `PublicKey` is protected by the `DownstreamKey`. This setup allows:
///
///   - Access to `DownstreamKey` by knowing the `UpstreamKey`
///   - Rotation to a `NewDownstreamKey` by knowing the current `DownstreamKey`, without needing
///     access to the `UpstreamKey`
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct RotateableKeySet {
    /// `DownstreamKey` protected by encapsulation key
    encapsulated_downstream_key: UnsignedSharedKey,
    /// Encapsulation key protected by `DownstreamKey`
    encrypted_encapsulation_key: EncString,
    /// Decapsulation key protected by `UpstreamKey`
    encrypted_decapsulation_key: EncString,
}

impl RotateableKeySet {
    /// Create a set of keys to allow access to the downstream key via the provided
    /// upstream key while allowing the downstream key to be rotated.
    pub fn new<Ids: KeyIds>(
        ctx: &KeyStoreContext<Ids>,
        upstream_key: &SymmetricCryptoKey,
        downstream_key_id: Ids::Symmetric,
    ) -> Result<Self, CryptoError> {
        let key_pair = AsymmetricCryptoKey::make(crate::PublicKeyEncryptionAlgorithm::RsaOaepSha1);

        // This uses this deprecated method and other methods directly on the other keys
        // rather than the key store context because we don't want the keys to
        // wind up being stored in the borrowed context.
        #[allow(deprecated)]
        let downstream_key = ctx.dangerous_get_symmetric_key(downstream_key_id)?;
        // encapsulate downstream key
        let encapsulated_downstream_key =
            UnsignedSharedKey::encapsulate_key_unsigned(downstream_key, &key_pair.to_public_key())?;

        // wrap decapsulation key with upstream key
        let encrypted_decapsulation_key = key_pair.to_der()?.encrypt_with_key(upstream_key)?;

        // wrap encapsulation key with downstream key
        // Note: Usually, a public key is - by definition - public, so this should not be necessary.
        // The specific use-case for this function is to enable rotateable key sets, where
        // the "public key" is not public, with the intent of preventing the server from being able
        // to overwrite the downstream key unlocked by the rotateable keyset.
        let encrypted_encapsulation_key = key_pair
            .to_public_key()
            .to_der()?
            .encrypt_with_key(downstream_key)?;

        Ok(RotateableKeySet {
            encapsulated_downstream_key,
            encrypted_encapsulation_key,
            encrypted_decapsulation_key,
        })
    }

    // TODO: Eventually, the webauthn-login-strategy service should be migrated
    // to use this method, and we can remove the #[allow(dead_code)] attribute.
    #[allow(dead_code)]
    fn unlock<Ids: KeyIds>(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        upstream_key: &SymmetricCryptoKey,
        downstream_key_id: Ids::Symmetric,
    ) -> Result<(), CryptoError> {
        let priv_key_bytes: Vec<u8> = self
            .encrypted_decapsulation_key
            .decrypt_with_key(upstream_key)?;
        let decapsulation_key =
            AsymmetricCryptoKey::from_der(&Pkcs8PrivateKeyBytes::from(priv_key_bytes))?;
        let downstream_key = self
            .encapsulated_downstream_key
            .decapsulate_key_unsigned(&decapsulation_key)?;
        #[allow(deprecated)]
        ctx.set_symmetric_key(downstream_key_id, downstream_key)?;
        Ok(())
    }
}

#[allow(dead_code)]
fn rotate_key_set<Ids: KeyIds>(
    ctx: &KeyStoreContext<Ids>,
    key_set: RotateableKeySet,
    old_downstream_key_id: Ids::Symmetric,
    new_downstream_key_id: Ids::Symmetric,
) -> Result<RotateableKeySet, CryptoError> {
    let pub_key_bytes = ctx.decrypt_data_with_symmetric_key(
        old_downstream_key_id,
        &key_set.encrypted_encapsulation_key,
    )?;
    let pub_key = SpkiPublicKeyBytes::from(pub_key_bytes);
    let encapsulation_key = AsymmetricPublicCryptoKey::from_der(&pub_key)?;
    // TODO: There is no method to store only the public key in the store, so we
    // have pull out the downstream key to encapsulate it manually.
    #[allow(deprecated)]
    let new_downstream_key = ctx.dangerous_get_symmetric_key(new_downstream_key_id)?;
    let new_encapsulated_key =
        UnsignedSharedKey::encapsulate_key_unsigned(new_downstream_key, &encapsulation_key)?;
    let new_encrypted_encapsulation_key = pub_key.encrypt_with_key(new_downstream_key)?;
    Ok(RotateableKeySet {
        encapsulated_downstream_key: new_encapsulated_key,
        encrypted_encapsulation_key: new_encrypted_encapsulation_key,
        encrypted_decapsulation_key: key_set.encrypted_decapsulation_key,
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

    #[test]
    fn test_rotateable_key_set_can_unlock() {
        // generate initial keys
        let upstream_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        // set up store
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let original_downstream_key_id = TestSymmKey::A(0);
        ctx.generate_symmetric_key(original_downstream_key_id)
            .unwrap();

        // create key set
        let key_set =
            RotateableKeySet::new(&ctx, &upstream_key, original_downstream_key_id).unwrap();

        // unlock key set
        let unwrapped_downstream_key_id = TestSymmKey::A(1);
        key_set
            .unlock(&mut ctx, &upstream_key, unwrapped_downstream_key_id)
            .unwrap();

        #[allow(deprecated)]
        let original_downstream_key = ctx
            .dangerous_get_symmetric_key(original_downstream_key_id)
            .unwrap();
        #[allow(deprecated)]
        let unwrapped_downstream_key = ctx
            .dangerous_get_symmetric_key(unwrapped_downstream_key_id)
            .unwrap();
        assert_eq!(original_downstream_key, unwrapped_downstream_key);
    }

    #[test]
    fn test_rotateable_key_set_rotation() {
        // generate initial keys
        let upstream_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        // set up store
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let original_downstream_key_id = TestSymmKey::A(1);
        ctx.generate_symmetric_key(original_downstream_key_id)
            .unwrap();

        // create key set
        let key_set =
            RotateableKeySet::new(&ctx, &upstream_key, original_downstream_key_id).unwrap();

        // rotate
        let new_downstream_key_id = TestSymmKey::A(2_1);
        ctx.generate_symmetric_key(new_downstream_key_id).unwrap();
        let new_key_set = rotate_key_set(
            &ctx,
            key_set,
            original_downstream_key_id,
            new_downstream_key_id,
        )
        .unwrap();

        // After rotation, the new key set should be unlocked by the same
        // upstream key and return the new downstream key.
        let unwrapped_downstream_key_id = TestSymmKey::A(2_2);
        new_key_set
            .unlock(&mut ctx, &upstream_key, unwrapped_downstream_key_id)
            .unwrap();
        #[allow(deprecated)]
        let new_downstream_key = ctx
            .dangerous_get_symmetric_key(new_downstream_key_id)
            .unwrap();
        #[allow(deprecated)]
        let unwrapped_downstream_key = ctx
            .dangerous_get_symmetric_key(unwrapped_downstream_key_id)
            .unwrap();
        assert_eq!(new_downstream_key, unwrapped_downstream_key);
    }
}
