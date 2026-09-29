use bitwarden_core::key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId};
use bitwarden_crypto::{Decryptable, KeyStoreContext, UnsignedSharedKey};

use crate::{
    Cipher, CipherView, CiphersClient, DecryptCipherResult, DecryptError,
    cipher::cipher::StrictDecrypt,
};

impl CiphersClient {
    /// Decrypts ciphers encrypted under a key that was shared with the current user.
    ///
    /// `shared_key` is a symmetric key encapsulated to the current user's public key, e.g. an
    /// emergency access grantor's user key. It is decapsulated into a local key slot and used in
    /// place of each cipher's natural `User`/`Organization` slot, so it never leaves the key store.
    /// Ciphers that fail to decrypt are returned in `failures`.
    ///
    /// Not exposed to bindings; feature clients wrap it.
    pub async fn decrypt_list_with_shared_key(
        &self,
        shared_key: UnsignedSharedKey,
        ciphers: Vec<Cipher>,
    ) -> Result<DecryptCipherResult, DecryptError> {
        let use_strict_decryption = self.is_strict_decrypt().await;

        // Keep one context for the whole list; clearing local keys would drop the shared key.
        let mut ctx = self.key_store.context();
        let key_id = shared_key.decapsulate(PrivateKeySlotId::UserPrivateKey, &mut ctx)?;

        let mut successes = Vec::with_capacity(ciphers.len());
        let mut failures = Vec::new();
        for cipher in ciphers {
            match decrypt_one(&cipher, &mut ctx, key_id, use_strict_decryption) {
                Ok(view) => successes.push(view),
                Err(_) => failures.push(cipher),
            }
        }

        Ok(DecryptCipherResult {
            successes,
            failures,
        })
    }
}

fn decrypt_one(
    cipher: &Cipher,
    ctx: &mut KeyStoreContext<KeySlotIds>,
    key: SymmetricKeySlotId,
    use_strict_decryption: bool,
) -> Result<CipherView, bitwarden_crypto::CryptoError> {
    if use_strict_decryption {
        return StrictDecrypt(cipher.clone()).decrypt(ctx, key);
    }

    cipher.decrypt(ctx, key)
}
