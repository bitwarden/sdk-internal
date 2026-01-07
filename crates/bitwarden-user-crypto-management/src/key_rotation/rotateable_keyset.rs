use bitwarden_api_api::models::{
    OtherDeviceKeysUpdateRequestModel, WebAuthnLoginRotateKeyRequestModel,
};
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    AsymmetricPublicCryptoKey, Decryptable, EncString, KeyStoreContext, PrimitiveEncryptable,
    UnsignedSharedKey,
};
use tracing::instrument;

/// A version of a rotateable keyset, missing the upstream-key-encrypted-private-key.
/// This can only be used to re-share the downstream-key (in this case the user-key) with the
/// key-set.
pub(super) struct KeysetUnlockData {
    pub(super) id: uuid::Uuid,
    pub(super) encrypted_public_key: EncString,
    pub(super) encrypted_user_key: UnsignedSharedKey,
}

impl From<KeysetUnlockData> for OtherDeviceKeysUpdateRequestModel {
    fn from(val: KeysetUnlockData) -> Self {
        OtherDeviceKeysUpdateRequestModel {
            device_id: val.id,
            encrypted_public_key: val.encrypted_public_key.to_string(),
            encrypted_user_key: val.encrypted_user_key.to_string(),
        }
    }
}

impl From<KeysetUnlockData> for WebAuthnLoginRotateKeyRequestModel {
    fn from(val: KeysetUnlockData) -> Self {
        WebAuthnLoginRotateKeyRequestModel {
            id: val.id,
            encrypted_public_key: val.encrypted_public_key.to_string(),
            encrypted_user_key: val.encrypted_user_key.to_string(),
        }
    }
}

impl KeysetUnlockData {
    #[instrument(skip(self, ctx))]
    pub(super) fn reencrypt(
        &self,
        current_user_key_id: SymmetricKeyId,
        new_user_key_id: SymmetricKeyId,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<KeysetUnlockData, ()> {
        let pubkey_bytes: Vec<u8> = self
            .encrypted_public_key
            .decrypt(ctx, current_user_key_id)
            .map_err(|_| ())?;
        let pubkey_der =
            bitwarden_crypto::Bytes::<bitwarden_crypto::SpkiPublicKeyDerContentFormat>::from(
                pubkey_bytes,
            );
        let pubkey = AsymmetricPublicCryptoKey::from_der(&pubkey_der).map_err(|_| ())?;
        let reencrypted_user_key =
            UnsignedSharedKey::encapsulate(new_user_key_id, &pubkey, ctx).map_err(|_| ())?;
        let reencrypted_public_key = pubkey_der
            .encrypt(ctx, current_user_key_id)
            .map_err(|_| ())?;
        Ok(KeysetUnlockData {
            id: self.id,
            encrypted_public_key: reencrypted_public_key,
            encrypted_user_key: reencrypted_user_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::KeyIds;
    use bitwarden_crypto::KeyStore;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn test_keyset_reencrypt() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        // Generate two symmetric keys, old and new
        let key_id_1 = ctx.generate_symmetric_key();
        let key_id_2 = ctx.generate_symmetric_key();

        // Generate an asymmetric key pair and encapsulate a symmetric key
        let private_key = ctx.make_asymmetric_key();
        let pubkey_der = ctx.get_public_key(private_key).unwrap().to_der().unwrap();
        let encrypted_public_key = pubkey_der.encrypt(&mut ctx, key_id_1).unwrap();

        let encrypted_user_key = UnsignedSharedKey::encapsulate(
            key_id_1,
            &ctx.get_public_key(private_key).unwrap(),
            &ctx,
        )
        .unwrap();

        // Create a KeysetUnlockData
        let keyset = KeysetUnlockData {
            id: Uuid::new_v4(),
            encrypted_public_key,
            encrypted_user_key,
        };

        // Re-encrypt the keyset with the new key
        let reencrypted = keyset
            .reencrypt(key_id_1, key_id_2, &mut ctx)
            .expect("reencrypt should succeed");

        // Check that the re-encrypted user key can be decapsulated to the same symmetric key
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
    }
}
