use std::num::NonZeroU32;

use coset::CborSerializable;
use zeroize::Zeroizing;

use crate::kdf::{Kdf, KdfDerivedKeyMaterial};
use crate::{cose, CryptoError, EncString, SymmetricCryptoKey};
use crate::keys::stretch_key;

pub struct KeyEnvelopeWithoutKdfParameters(EncString);
pub struct KeyEnvelopeWithKdfParameters(EncString);

pub enum PasswordProtectedKeyEnvelope {
    WithKdfParameters(KeyEnvelopeWithKdfParameters),
    WithoutKdfParameters(KeyEnvelopeWithoutKdfParameters),
}

impl Into<EncString> for PasswordProtectedKeyEnvelope {
    fn into(self) -> EncString {
        match self {
            PasswordProtectedKeyEnvelope::WithKdfParameters(envelope) => envelope.0,
            PasswordProtectedKeyEnvelope::WithoutKdfParameters(envelope) => envelope.0,
        }
    }
}

impl From<EncString> for PasswordProtectedKeyEnvelope {
    fn from(envelope: EncString) -> Self {
        match envelope {
            EncString::XChaCha20_Poly1305_Cose_B64 { .. } => {
                PasswordProtectedKeyEnvelope::WithKdfParameters(KeyEnvelopeWithKdfParameters(envelope))
            }
            EncString::AesCbc256_HmacSha256_B64 { .. } => {
                PasswordProtectedKeyEnvelope::WithoutKdfParameters(KeyEnvelopeWithoutKdfParameters(envelope))
            }
            EncString::AesCbc256_B64 { .. } => {
                PasswordProtectedKeyEnvelope::WithoutKdfParameters(KeyEnvelopeWithoutKdfParameters(envelope))
            }
        }
    }
}

impl PasswordProtectedKeyEnvelope {
    pub fn seal(key: &SymmetricCryptoKey, password: &str, salt: &[u8], kdf: &Kdf) -> Result<Self, CryptoError> {
        let kdf_derived_key = KdfDerivedKeyMaterial::derive_kdf_key(password.as_bytes(), salt, kdf)?;

        // Switch once clients support widely
        if true {
            let stretched_kdf_derived_key = stretch_key(&kdf_derived_key.material)?;
            let key_bytes = Zeroizing::new(key.to_encoded());
            let encrypted = EncString::encrypt_aes256_hmac(&key_bytes, &stretched_kdf_derived_key)?;
            let envelope = KeyEnvelopeWithoutKdfParameters(encrypted);
            Ok(Self::WithoutKdfParameters(envelope))
        } else {
            let mut protected_header = coset::HeaderBuilder::new().build();
            protected_header.alg = Some(coset::Algorithm::PrivateUse(cose::XCHACHA20_POLY1305));
            let header = cose_header_for_kdf(kdf, salt);
            let mut nonce = [0u8; 24];
            let cose_encrypt = coset::CoseEncryptBuilder::new()
                .protected(protected_header)
                .add_recipient(coset::CoseRecipientBuilder::new()
                    .protected(header)
                    .build())
                .create_ciphertext(&key.to_encoded(), &[], |data, aad| {
                    let ciphertext = crate::xchacha20::encrypt_xchacha20_poly1305(
                        kdf_derived_key.material
                            .as_slice()
                            .try_into()
                            .expect("XChaChaPoly1305 key is 32 bytes long"),
                        data,
                        aad,
                    );
                    nonce.copy_from_slice(ciphertext.nonce.as_slice());
                    ciphertext.ciphertext
                })
                .build();
            let bytes = cose_encrypt.to_vec().unwrap();
            let encstring = EncString::XChaCha20_Poly1305_Cose_B64 { data: bytes.clone() };
            Ok(Self::WithKdfParameters(KeyEnvelopeWithKdfParameters(encstring)))
        }
    }
}

impl KeyEnvelopeWithKdfParameters {
    pub fn unseal(
        &self,
        password: &[u8],
    ) -> Result<SymmetricCryptoKey, CryptoError> {
        let mut decrypted_key: Vec<u8> = match self.0 {
            EncString::XChaCha20_Poly1305_Cose_B64 { .. } => {
                todo!();
            },
            _ => unreachable!(),
        };
        SymmetricCryptoKey::try_from(decrypted_key.as_mut_slice())
    }
}

impl KeyEnvelopeWithoutKdfParameters {
    pub fn unseal(
        &self,
        password: &[u8],
        salt: &[u8],
        kdf: &Kdf,
    ) -> Result<SymmetricCryptoKey, CryptoError> {
        match self.0 {
            EncString::AesCbc256_HmacSha256_B64 { .. } => {
                todo!();
            }
            EncString::AesCbc256_B64 { .. } => {
                todo!();
            }
            _ => unreachable!(),
        }
    }
}

fn kdf_params_for_cose_header(
    header: coset::Header,
) -> Result<(Kdf, Vec<u8>), CryptoError> {
    let mut kdf_type = None;
    let mut kdf_iterations= None;
    let mut kdf_memory = None;
    let mut kdf_parallelism = None;

    let mut salt = None;

    for (key, value) in header.rest {
        if let coset::Label::Text(text) = key {
            match text.as_str() {
                "kdf" => {
                    let kdf_text = value.clone();
                    let kdf_text = kdf_text.into_text().map_err(|_| CryptoError::InsufficientKdfParameters)?;
                    kdf_type = Some(kdf_text.clone());
                }
                "iterations" => {
                    let iterations: u32 = u128::try_from(value.clone().as_integer().unwrap()).unwrap() as u32;
                    kdf_iterations = Some(iterations);
                },
                "memory_mib" => {
                    let memory: u32 = u128::try_from(value.clone().as_integer().unwrap()).unwrap() as u32;
                    kdf_memory = Some(memory);
                },
                "parallelism" => {
                    let parallelism: u32 = u128::try_from(value.clone().as_integer().unwrap()).unwrap() as u32;
                    kdf_parallelism = Some(parallelism);
                },
                "salt" => salt = Some(text.clone()),
                _ => {}
            }
        }
    }

    if let (Some(kdf_type), Some(kdf_iterations), Some(salt)) = (kdf_type, kdf_iterations, salt) {
        let kdf = match kdf_type.as_str() {
            "pbkdf2" => {
                Kdf::PBKDF2 { iterations: NonZeroU32::new(kdf_iterations).ok_or(CryptoError::InsufficientKdfParameters)? }
            }
            "argon2id" => {
                let kdf_memory = kdf_memory.ok_or(CryptoError::InsufficientKdfParameters)?;
                let kdf_parallelism = kdf_parallelism.ok_or(CryptoError::InsufficientKdfParameters)?;
                Kdf::Argon2id {
                    iterations: NonZeroU32::new(kdf_iterations).ok_or(CryptoError::InsufficientKdfParameters)?,
                    memory: NonZeroU32::new(kdf_memory).ok_or(CryptoError::InsufficientKdfParameters)?,
                    parallelism: NonZeroU32::new(kdf_parallelism).ok_or(CryptoError::InsufficientKdfParameters)?,
                }
            }
            _ => return Err(CryptoError::InsufficientKdfParameters),
        };
        Ok((kdf, salt.as_bytes().to_vec()))
    } else {
        Err(CryptoError::InsufficientKdfParameters)
    }
}

fn cose_header_for_kdf(
    kdf: &Kdf,
    salt: &[u8],
) -> coset::Header {
    // Password protected receivers are intended by COSE but not standardized.
    // A password protected key is represented as a CoseEncrypt message with a single
    // receiver. The receiver contains a protected header with the KDF parameters.
    let header_builder = coset::HeaderBuilder::new();
    let header = match kdf {
        Kdf::PBKDF2 { iterations } => {
            let iterations = iterations.get();
            header_builder
                .text_value("kdf".to_string(), ciborium::Value::Text("pbkdf2".to_string()))
                .text_value("iterations".to_string(), ciborium::Value::Integer(iterations.into()))
                .text_value("salt".to_string(), ciborium::Value::Bytes(salt.to_vec()))
                .build()
        }
        Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => {
            let iterations = iterations.get();
            let memory = memory.get();
            let parallelism = parallelism.get();
            header_builder
                .text_value("kdf".to_string(), ciborium::Value::Text("argon2id".to_string()))
                .text_value("iterations".to_string(), ciborium::Value::Integer(iterations.into()))
                .text_value("memory_mib".to_string(), ciborium::Value::Integer(memory.into()))
                .text_value("parallelism".to_string(), ciborium::Value::Integer(parallelism.into()))
                .text_value("salt".to_string(), ciborium::Value::Bytes(salt.to_vec()))
                .build()
        }
    };
    header
}