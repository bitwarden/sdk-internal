use bitwarden_api_api::models::{
    OtherDeviceKeysUpdateRequestModel, WebAuthnLoginRotateKeyRequestModel,
};
#[cfg(test)]
use bitwarden_core::key_management::PrivateKeyId;
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    Decryptable, EncString, KeyStoreContext, PrimitiveEncryptable, PublicKey, UnsignedSharedKey,
};
use tracing::instrument;

/// A version of a rotateable keyset, missing the upstream-key-encrypted-private-key.
/// This can only be used to re-share the downstream-key (in this case the user-key) with the
/// key-set.
pub(super) struct PartialRotateableKeyset {
    pub(super) id: uuid::Uuid,
    pub(super) encrypted_public_key: EncString,
    pub(super) encrypted_user_key: UnsignedSharedKey,
}

impl From<PartialRotateableKeyset> for OtherDeviceKeysUpdateRequestModel {
    fn from(val: PartialRotateableKeyset) -> Self {
        OtherDeviceKeysUpdateRequestModel {
            device_id: val.id,
            encrypted_public_key: val.encrypted_public_key.to_string(),
            encrypted_user_key: val.encrypted_user_key.to_string(),
        }
    }
}

impl From<PartialRotateableKeyset> for WebAuthnLoginRotateKeyRequestModel {
    fn from(val: PartialRotateableKeyset) -> Self {
        WebAuthnLoginRotateKeyRequestModel {
            id: val.id,
            encrypted_public_key: val.encrypted_public_key.to_string(),
            encrypted_user_key: val.encrypted_user_key.to_string(),
        }
    }
}

impl PartialRotateableKeyset {
    /// Makes a new `PartialRotateableKeyset` by re-encrypting the user-key. Specifically,
    /// the user-key-encrypted-public-key is re-encrypted for the new user-key, and the
    /// public-key-encrypted-user-key is re-created for the new user-key.
    #[instrument(skip(self, ctx))]
    pub(super) fn rotate_userkey(
        &self,
        current_user_key_id: SymmetricKeyId,
        new_user_key_id: SymmetricKeyId,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<PartialRotateableKeyset, ()> {
        let pubkey_bytes: Vec<u8> = self
            .encrypted_public_key
            .decrypt(ctx, current_user_key_id)
            .map_err(|_| ())?;
        let pubkey_der =
            bitwarden_crypto::Bytes::<bitwarden_crypto::SpkiPublicKeyDerContentFormat>::from(
                pubkey_bytes,
            );
        let pubkey = PublicKey::from_der(&pubkey_der).map_err(|_| ())?;
        let reencrypted_user_key =
            UnsignedSharedKey::encapsulate(new_user_key_id, &pubkey, ctx).map_err(|_| ())?;
        let reencrypted_public_key = pubkey_der.encrypt(ctx, new_user_key_id).map_err(|_| ())?;
        Ok(PartialRotateableKeyset {
            id: self.id,
            encrypted_public_key: reencrypted_public_key,
            encrypted_user_key: reencrypted_user_key,
        })
    }

    /// Makes a test `PartialRotateableKeyset` for the given downstream key.
    /// The private key is stored on the context since it is no present on the partial keyset.
    #[cfg(test)]
    pub(crate) fn make_test_keyset(
        downstream_key_id: SymmetricKeyId,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> (Self, PrivateKeyId) {
        use bitwarden_crypto::PublicKeyEncryptionAlgorithm;

        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let pubkey_der = ctx.get_public_key(private_key).unwrap().to_der().unwrap();
        let encrypted_public_key = pubkey_der.encrypt(ctx, downstream_key_id).unwrap();
        let encrypted_user_key = UnsignedSharedKey::encapsulate(
            downstream_key_id,
            &ctx.get_public_key(private_key).unwrap(),
            ctx,
        )
        .unwrap();
        (
            PartialRotateableKeyset {
                id: uuid::Uuid::new_v4(),
                encrypted_public_key,
                encrypted_user_key,
            },
            private_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::KeyIds;
    use bitwarden_crypto::{Bytes, KeyStore, SpkiPublicKeyDerContentFormat};

    use super::*;

    #[test]
    fn test_keyset_reencrypt() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        // Generate two symmetric keys, old and new
        let key_id_1 = ctx.generate_symmetric_key();
        let key_id_2 = ctx.generate_symmetric_key();

        // Generate an asymmetric key pair and encapsulate a symmetric key
        let (test_keyset, private_key) =
            PartialRotateableKeyset::make_test_keyset(key_id_1, &mut ctx);
        let pubkey_der = {
            let decrypted_pubkey_bytes: Vec<u8> = test_keyset
                .encrypted_public_key
                .decrypt(&mut ctx, key_id_1)
                .expect("decryption should succeed");
            Bytes::<SpkiPublicKeyDerContentFormat>::from(decrypted_pubkey_bytes)
        };

        // Re-encrypt the keyset with the new key
        let reencrypted = test_keyset
            .rotate_userkey(key_id_1, key_id_2, &mut ctx)
            .expect("reencrypt should succeed");

        // Check that the re-encrypted user key can be decapsulated and is the same symmetric key
        let decapsulated = {
            let decapsulated = reencrypted
                .encrypted_user_key
                .decapsulate(private_key, &mut ctx)
                .expect("decapsulation should succeed");
            #[expect(deprecated)]
            ctx.dangerous_get_symmetric_key(decapsulated)
                .expect("key should exist")
                .to_owned()
        };

        let key_2 = {
            #[expect(deprecated)]
            ctx.dangerous_get_symmetric_key(key_id_2)
                .expect("key should exist")
                .to_owned()
        };
        assert_eq!(decapsulated, key_2);

        // Check that the re-encyrpted public-key can be decrypted with the new key
        let decrypted_pubkey_bytes: Vec<u8> = reencrypted
            .encrypted_public_key
            .decrypt(&mut ctx, key_id_2)
            .expect("decryption should succeed");
        assert_eq!(decrypted_pubkey_bytes, pubkey_der.as_ref());
    }
}
