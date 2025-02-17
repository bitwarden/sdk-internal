use std::pin::Pin;

use generic_array::{typenum::U32, GenericArray};
use sha2::Digest;
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, EncString, Result};

use super::{utils::stretch_key, Kdf, KeyDecryptable, SymmetricCryptoKey};

pub(crate) trait KeyMaterial {
    // TODO: This should be made internal to this module
    fn inner_bytes(&self) -> &[u8];
}

pub(crate) struct KdfDerivedKeyMaterial(pub(crate) Pin<Box<GenericArray<u8, U32>>>);

impl KeyMaterial for KdfDerivedKeyMaterial {
    fn inner_bytes(&self) -> &[u8] {
        &self.0
    }
}

const PBKDF2_MIN_ITERATIONS: u32 = 5000;

const ARGON2ID_MIN_MEMORY: u32 = 16 * 1024;
const ARGON2ID_MIN_ITERATIONS: u32 = 2;
const ARGON2ID_MIN_PARALLELISM: u32 = 1;

impl KdfDerivedKeyMaterial {
    /// Derive a key from a secret and salt using the provided KDF.
    pub(super) fn derive_kdf_key(
        secret: &[u8],
        salt: &[u8],
        kdf: &Kdf,
    ) -> Result<Self, CryptoError> {
        let mut hash = match kdf {
            Kdf::PBKDF2 { iterations } => {
                let iterations = iterations.get();
                if iterations < PBKDF2_MIN_ITERATIONS {
                    return Err(CryptoError::InsufficientKdfParameters);
                }

                crate::util::pbkdf2(secret, salt, iterations)
            }
            Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => {
                let memory = memory.get() * 1024; // Convert MiB to KiB;
                let iterations = iterations.get();
                let parallelism = parallelism.get();

                if memory < ARGON2ID_MIN_MEMORY
                    || iterations < ARGON2ID_MIN_ITERATIONS
                    || parallelism < ARGON2ID_MIN_PARALLELISM
                {
                    return Err(CryptoError::InsufficientKdfParameters);
                }

                use argon2::*;

                let params = Params::new(memory, iterations, parallelism, Some(32))?;
                let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

                let salt_sha = sha2::Sha256::new().chain_update(salt).finalize();

                let mut hash = [0u8; 32];
                argon.hash_password_into(secret, &salt_sha, &mut hash)?;

                // Argon2 is using some stack memory that is not zeroed. Eventually some function
                // will overwrite the stack, but we use this trick to force the used
                // stack to be zeroed.
                #[inline(never)]
                fn clear_stack() {
                    std::hint::black_box([0u8; 4096]);
                }
                clear_stack();

                hash
            }
        };
        let key_material = Box::pin(GenericArray::clone_from_slice(&hash));
        hash.zeroize();
        Ok(KdfDerivedKeyMaterial(key_material))
    }

    /// Derives a users master key from their password, email and KDF.
    ///
    /// Note: the email is trimmed and converted to lowercase before being used.
    pub fn derive(password: &str, email: &str, kdf: &Kdf) -> Result<Self, CryptoError> {
        Self::derive_kdf_key(
            password.as_bytes(),
            email.trim().to_lowercase().as_bytes(),
            kdf,
        )
    }
}

pub(crate) struct RandomKeyMaterial(pub(crate) Pin<Box<GenericArray<u8, U32>>>);

impl KeyMaterial for RandomKeyMaterial {
    fn inner_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Helper function to encrypt a user key with a master or pin key.
pub(super) fn encrypt_user_key(
    key_material: &dyn KeyMaterial,
    user_key: &SymmetricCryptoKey,
) -> Result<EncString> {
    let stretched_master_key = stretch_key(key_material)?;
    let user_key_bytes = Zeroizing::new(user_key.to_vec());
    EncString::encrypt_aes256_hmac(&user_key_bytes, &stretched_master_key)
}

/// Helper function to decrypt a user key with a master or pin key.
pub(super) fn decrypt_user_key(
    key_material: &dyn KeyMaterial,
    user_key: EncString,
) -> Result<SymmetricCryptoKey> {
    let mut dec: Vec<u8> = match user_key {
        // Legacy. user_keys were encrypted using `AesCbc256_B64` a long time ago. We've since
        // moved to using `AesCbc256_HmacSha256_B64`. However, we still need to support
        // decrypting these old keys.
        EncString::AesCbc256_B64 { .. } => {
            let legacy_key = SymmetricCryptoKey::Aes256CbcKey(super::Aes256CbcKey {
                enc_key: Box::pin(GenericArray::clone_from_slice(key_material)),
            });
            user_key.decrypt_with_key(&legacy_key)?
        }
        _ => {
            let stretched_key = SymmetricCryptoKey::Aes256CbcHmacKey(stretch_key(key_material)?);
            user_key.decrypt_with_key(&stretched_key)?
        }
    };

    SymmetricCryptoKey::try_from(dec.as_mut_slice())
}
