//! Variants of the list decrypts that the performance harnesses in `e2e/wasm/perf` compare
//! against. Only built with the `perf-baselines` feature, which no shipped build enables.

use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::Decryptable;
use bitwarden_ffi::LargeVec;

use super::{CiphersClient, decrypt_ciphers};
use crate::{
    Cipher, CipherListView, CipherView, DecryptCipherListResult, DecryptCipherResult,
    DecryptListError, cipher::cipher::StrictDecrypt,
};

#[bitwarden_ffi::wasm_export]
impl CiphersClient {
    /// [`Self::decrypt_list_with_failures`] with the ciphers converted in full when the call
    /// starts, as wasm_bindgen converts a `Vec` parameter.
    pub async fn decrypt_list_with_failures_eager(
        &self,
        ciphers: Vec<Cipher>,
    ) -> Result<DecryptCipherListResult, DecryptListError> {
        self.decrypt_list_with_failures(ciphers.into()).await
    }

    /// [`Self::decrypt_list_full_with_failures`] with the ciphers converted in full when the call
    /// starts, as wasm_bindgen converts a `Vec` parameter.
    pub async fn decrypt_list_full_with_failures_eager(
        &self,
        ciphers: Vec<Cipher>,
    ) -> Result<DecryptCipherResult, DecryptListError> {
        self.decrypt_list_full_with_failures(ciphers.into()).await
    }

    /// [`Self::decrypt_list_with_failures`] without its output: each result is dropped as it is
    /// read, and only the number of successes is returned. The memory it needs is that of the
    /// input path alone.
    pub async fn decrypt_list_with_failures_count(
        &self,
        ciphers: LargeVec<Cipher>,
    ) -> Result<u32, DecryptListError> {
        self.decrypt_list_count::<CipherListView>(ciphers).await
    }

    /// [`Self::decrypt_list_full_with_failures`] without its output, as
    /// [`Self::decrypt_list_with_failures_count`] is for list views.
    pub async fn decrypt_list_full_with_failures_count(
        &self,
        ciphers: LargeVec<Cipher>,
    ) -> Result<u32, DecryptListError> {
        self.decrypt_list_count::<CipherView>(ciphers).await
    }
}

#[allow(deprecated)]
impl CiphersClient {
    /// Decrypts `ciphers` as `decrypt_ciphers_with_failures` does, but drops each decrypted and
    /// failed cipher, and returns the number that decrypted.
    async fn decrypt_list_count<Output>(
        &self,
        ciphers: LargeVec<Cipher>,
    ) -> Result<u32, DecryptListError>
    where
        Cipher: Decryptable<KeySlotIds, SymmetricKeySlotId, Output>,
        StrictDecrypt<Cipher>: Decryptable<KeySlotIds, SymmetricKeySlotId, Output>,
        Output: Send,
    {
        let key_store = self.client.internal.get_key_store();
        let strict = self.is_strict_decrypt().await;
        let mut count = 0;
        for result in decrypt_ciphers::<Output>(key_store, ciphers, strict) {
            if result?.is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }
}
