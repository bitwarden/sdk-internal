use std::{num::NonZeroU32, pin::Pin};

use generic_array::{typenum::U32, GenericArray};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::Digest;
#[cfg(feature = "wasm")]
use tsify_next::Tsify;
use zeroize::Zeroize;

use crate::CryptoError;

const PBKDF2_MIN_ITERATIONS: u32 = 5000;

const ARGON2ID_MIN_MEMORY: u32 = 16 * 1024;
const ARGON2ID_MIN_ITERATIONS: u32 = 2;
const ARGON2ID_MIN_PARALLELISM: u32 = 1;

/// Holding struct for key material derived from a KDF.
///
/// The internal key material should not be used directly for cryptographic operations. Instead it
/// MUST be converted to the appropriate type such as `SymmetricCryptoKey`, `MasterKey` or any other
/// key type. This can be done by either directly consuming the key material or by stretching it
/// further using HKDF (HMAC-based Key Derivation Function).
///
/// Uses a pinned heap data structure, as noted in [Pinned heap data][crate#pinned-heap-data]
pub struct KdfDerivedKeyMaterial(pub(super) Pin<Box<GenericArray<u8, U32>>>);

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
    pub(super) fn derive(password: &str, email: &str, kdf: &Kdf) -> Result<Self, CryptoError> {
        Self::derive_kdf_key(
            password.as_bytes(),
            email.trim().to_lowercase().as_bytes(),
            kdf,
        )
    }
}

/// Key Derivation Function for Bitwarden Account
///
/// In Bitwarden accounts can use multiple KDFs to derive their master key from their password. This
/// Enum represents all the possible KDFs.
#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum Kdf {
    PBKDF2 {
        iterations: NonZeroU32,
    },
    Argon2id {
        iterations: NonZeroU32,
        memory: NonZeroU32,
        parallelism: NonZeroU32,
    },
}

impl Default for Kdf {
    /// Default KDF for new accounts.
    fn default() -> Self {
        Kdf::PBKDF2 {
            iterations: default_pbkdf2_iterations(),
        }
    }
}

/// Default PBKDF2 iterations
pub fn default_pbkdf2_iterations() -> NonZeroU32 {
    NonZeroU32::new(600_000).expect("Non-zero number")
}
/// Default Argon2 iterations
pub fn default_argon2_iterations() -> NonZeroU32 {
    NonZeroU32::new(3).expect("Non-zero number")
}
/// Default Argon2 memory
pub fn default_argon2_memory() -> NonZeroU32 {
    NonZeroU32::new(64).expect("Non-zero number")
}
/// Default Argon2 parallelism
pub fn default_argon2_parallelism() -> NonZeroU32 {
    NonZeroU32::new(4).expect("Non-zero number")
}

#[cfg(test)]
mod tests {
    use std::num::{NonZero, NonZeroU32};

    use crate::keys::kdf::{Kdf, KdfDerivedKeyMaterial};

    #[test]
    fn test_derive_kdf_minimums() {
        fn nz(n: u32) -> NonZero<u32> {
            NonZero::new(n).unwrap()
        }

        let secret = [0u8; 32];
        let salt = [0u8; 32];

        for kdf in [
            Kdf::PBKDF2 {
                iterations: nz(4999),
            },
            Kdf::Argon2id {
                iterations: nz(1),
                memory: nz(16),
                parallelism: nz(1),
            },
            Kdf::Argon2id {
                iterations: nz(2),
                memory: nz(15),
                parallelism: nz(1),
            },
            Kdf::Argon2id {
                iterations: nz(1),
                memory: nz(15),
                parallelism: nz(1),
            },
        ] {
            assert_eq!(
                KdfDerivedKeyMaterial::derive_kdf_key(&secret, &salt, &kdf)
                    .err()
                    .unwrap()
                    .to_string(),
                "Insufficient KDF parameters"
            );
        }
    }

    #[test]
    fn test_master_key_derive_pbkdf2() {
        let kdf_key = KdfDerivedKeyMaterial::derive(
            "67t9b5g67$%Dh89n",
            "test_key",
            &Kdf::PBKDF2 {
                iterations: NonZeroU32::new(10000).unwrap(),
            },
        )
        .unwrap();

        assert_eq!(
            [
                31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167,
                69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75
            ],
            kdf_key.0.as_slice()
        );
    }

    #[test]
    fn test_master_key_derive_argon2() {
        let kdf_key = KdfDerivedKeyMaterial::derive(
            "67t9b5g67$%Dh89n",
            "test_key",
            &Kdf::Argon2id {
                iterations: NonZeroU32::new(4).unwrap(),
                memory: NonZeroU32::new(32).unwrap(),
                parallelism: NonZeroU32::new(2).unwrap(),
            },
        )
        .unwrap();

        assert_eq!(
            [
                207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240, 20, 147,
                237, 47, 246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242
            ],
            kdf_key.0.as_slice()
        );
    }
}
