use ciborium::Value;
use coset::{CoseEncrypt0, CoseEncrypt0Builder, Header, HeaderBuilder};
use subtle::ConstantTimeEq;

use crate::{
    Aes256CbcHmacKey, BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, CryptoError, EncString,
    EncodedSymmetricKey, SymmetricCryptoKey, XChaCha20Poly1305Key,
    cose::{AES256_CBC_HMAC, CONTAINED_KEY_ID, SafeObjectNamespace, XCHACHA20_POLY1305},
    safe::{
        SymmetricKeyEnvelopeError, SymmetricKeyEnvelopeNamespace,
        helpers::{set_safe_namespaces, validate_safe_namespaces},
    },
    xchacha20,
};

pub(crate) fn symmetric_key_seal_key_into_cose(
    key_to_seal: &SymmetricCryptoKey,
    sealing_key: &SymmetricCryptoKey,
    namespace: SymmetricKeyEnvelopeNamespace,
) -> Result<CoseEncrypt0, SymmetricKeyEnvelopeError> {
    match sealing_key {
        SymmetricCryptoKey::XChaCha20Poly1305Key(key) => {
            key.wrap_cose_encrypt0_ciphertext(key_to_seal, namespace)
        }
        SymmetricCryptoKey::Aes256CbcHmacKey(key) => {
            key.wrap_cose_encrypt0_ciphertext(key_to_seal, namespace)
        }
        _ => Err(SymmetricKeyEnvelopeError::WrongKeyType),
    }
}

pub(crate) fn symmetric_key_unseal_key_from_cose(
    sealing_key: &SymmetricCryptoKey,
    ciphertext: &CoseEncrypt0,
    namespace: SymmetricKeyEnvelopeNamespace,
) -> Result<SymmetricCryptoKey, SymmetricKeyEnvelopeError> {
    match sealing_key {
        SymmetricCryptoKey::XChaCha20Poly1305Key(key) => {
            key.unwrap_cose_encrypt0_ciphertext(ciphertext, namespace)
        }
        SymmetricCryptoKey::Aes256CbcHmacKey(key) => {
            key.unwrap_cose_encrypt0_ciphertext(ciphertext, namespace)
        }
        _ => Err(SymmetricKeyEnvelopeError::WrongKeyType),
    }
}

trait SymmetricCoseEncrypt0EnvelopeKey {
    fn wrap_cose_encrypt0_ciphertext(
        &self,
        key_to_seal: &SymmetricCryptoKey,
        namespace: SymmetricKeyEnvelopeNamespace,
    ) -> Result<CoseEncrypt0, SymmetricKeyEnvelopeError>;
    fn unwrap_cose_encrypt0_ciphertext(
        &self,
        cose_ciphertext: &CoseEncrypt0,
        namespace: SymmetricKeyEnvelopeNamespace,
    ) -> Result<SymmetricCryptoKey, SymmetricKeyEnvelopeError>;
}

impl SymmetricCoseEncrypt0EnvelopeKey for XChaCha20Poly1305Key {
    fn wrap_cose_encrypt0_ciphertext(
        &self,
        key_to_seal: &SymmetricCryptoKey,
        namespace: SymmetricKeyEnvelopeNamespace,
    ) -> Result<CoseEncrypt0, SymmetricKeyEnvelopeError> {
        let (mut protected_header, key_bytes) = build_cose_encrypt0_header(key_to_seal, namespace);
        protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));
        protected_header.key_id = self.key_id.as_slice().into();

        let cose_encrypt0_builder = CoseEncrypt0Builder::new().protected(protected_header);

        let mut nonce = [0u8; xchacha20::NONCE_SIZE];
        Ok(cose_encrypt0_builder
            .create_ciphertext(&key_bytes, &[], |data, aad| {
                let ciphertext =
                    xchacha20::encrypt_xchacha20_poly1305(&(*self.enc_key).into(), data, aad);
                nonce = ciphertext.nonce();
                ciphertext.encrypted_bytes().to_vec()
            })
            .unprotected(coset::HeaderBuilder::new().iv(nonce.to_vec()).build())
            .build())
    }

    fn unwrap_cose_encrypt0_ciphertext(
        &self,
        cose_ciphertext: &CoseEncrypt0,
        namespace: SymmetricKeyEnvelopeNamespace,
    ) -> Result<SymmetricCryptoKey, SymmetricKeyEnvelopeError> {
        validate_safe_namespaces(
            &cose_ciphertext.protected.header,
            SafeObjectNamespace::SymmetricKeyEnvelope,
            namespace,
        )
        .map_err(|_| SymmetricKeyEnvelopeError::InvalidNamespace)?;

        // Validate the content format
        let content_format =
            ContentFormat::try_from(&cose_ciphertext.protected.header).map_err(|_| {
                SymmetricKeyEnvelopeError::Parsing("Invalid content format".to_string())
            })?;

        let nonce: [u8; xchacha20::NONCE_SIZE] = cose_ciphertext
            .unprotected
            .iv
            .clone()
            .try_into()
            .map_err(|_| SymmetricKeyEnvelopeError::WrongKey)?;

        let key_bytes = cose_ciphertext
            .clone()
            .decrypt_ciphertext(
                &[],
                || CryptoError::MissingField("ciphertext"),
                |data, aad| {
                    xchacha20::decrypt_xchacha20_poly1305(
                        &nonce,
                        &(*self.enc_key).into(),
                        data,
                        aad,
                    )
                },
            )
            .map_err(|_| SymmetricKeyEnvelopeError::WrongKey)?;

        // Reconstruct the encoded symmetric key from the content format
        let encoded_key = match content_format {
            ContentFormat::BitwardenLegacyKey => {
                EncodedSymmetricKey::BitwardenLegacyKey(BitwardenLegacyKeyBytes::from(key_bytes))
            }
            ContentFormat::CoseKey => EncodedSymmetricKey::CoseKey(CoseKeyBytes::from(key_bytes)),
            _ => {
                return Err(SymmetricKeyEnvelopeError::WrongKeyType);
            }
        };

        SymmetricCryptoKey::try_from(encoded_key)
            .map_err(|_| SymmetricKeyEnvelopeError::WrongKeyType)
    }
}

impl SymmetricCoseEncrypt0EnvelopeKey for Aes256CbcHmacKey {
    /// Per [RFC 9052](https://datatracker.ietf.org/doc/rfc9052/)
    /// Section 5.4, encryption for AE algorithms requires:
    /// 1. protected field must be a zero-byte string
    /// 2. verify there was no external aad supplied for this operation
    fn wrap_cose_encrypt0_ciphertext(
        &self,
        key_to_seal: &SymmetricCryptoKey,
        namespace: SymmetricKeyEnvelopeNamespace,
    ) -> Result<CoseEncrypt0, SymmetricKeyEnvelopeError> {
        let (mut unprotected_header, key_bytes) =
            build_cose_encrypt0_header(key_to_seal, namespace);
        unprotected_header.alg = Some(coset::Algorithm::PrivateUse(AES256_CBC_HMAC));
        // no key id to set

        let mut iv = [0u8; 16];
        let cose_encrypt0_builder =
            // As per RFC 9052, section 5.4 external aad is empty
            // and ::new() means that protected header is empty
            CoseEncrypt0Builder::new().try_create_ciphertext(&key_bytes, &[], |plaintext, _aad| {
                let mac: [u8; 32];
                let data: Vec<u8>;

                (iv, mac, data) =
                    crate::aes::encrypt_aes256_hmac(plaintext, &self.mac_key, &self.enc_key)
                        .map_err(|_| CryptoError::Encrypt)?;

                EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data }
                    .to_buffer()
            }).map_err(|_| SymmetricKeyEnvelopeError::EncryptionFailed)?;

        unprotected_header.iv = iv.to_vec();

        let cose_encrypt0 = cose_encrypt0_builder
            .unprotected(unprotected_header)
            .build();

        Ok(cose_encrypt0)
    }

    /// In order to properly and securely decrypt an AE cose encrypt0:
    /// 1. Verify that the "protected" field is a zero-length string
    /// 2. Verify no additional external aad is supplied during this operation
    fn unwrap_cose_encrypt0_ciphertext(
        &self,
        cose_ciphertext: &CoseEncrypt0,
        namespace: SymmetricKeyEnvelopeNamespace,
    ) -> Result<SymmetricCryptoKey, SymmetricKeyEnvelopeError> {
        // verify the protected field is empty
        if !cose_ciphertext.protected.is_empty() {
            return Err(SymmetricKeyEnvelopeError::IncorrectCiphertextStructure);
        }

        validate_safe_namespaces(
            &cose_ciphertext.unprotected,
            SafeObjectNamespace::SymmetricKeyEnvelope,
            namespace,
        )
        .map_err(|_| SymmetricKeyEnvelopeError::InvalidNamespace)?;

        // Validate the content format
        let content_format =
            ContentFormat::try_from(&cose_ciphertext.unprotected).map_err(|_| {
                SymmetricKeyEnvelopeError::Parsing("Invalid content format".to_string())
            })?;

        let unprotected_iv: [u8; 16] = cose_ciphertext
            .unprotected
            .iv
            .clone()
            .try_into()
            .map_err(|_| SymmetricKeyEnvelopeError::IncorrectCiphertextStructure)?;

        let key_bytes = cose_ciphertext
            .clone()
            .decrypt_ciphertext(
                &[], // external aad is empty as per RFC 9052 section 5.4
                || CryptoError::MissingField("ciphertext"),
                |ciphertext, _aad| match EncString::from_buffer(ciphertext)
                    .map_err(|_| CryptoError::KeyDecrypt)?
                {
                    EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, ref data } => {
                        if iv.ct_ne(&unprotected_iv).into() {
                            return Err(CryptoError::InvalidKey);
                        }
                        crate::aes::decrypt_aes256_hmac(
                            &iv,
                            &mac,
                            data.clone(),
                            &self.mac_key,
                            &self.enc_key,
                        )
                        .map_err(|_| CryptoError::Decrypt)
                    }
                    _ => {
                        tracing::warn!(
                            "Unsupported decryption operation for the given key and data"
                        );
                        Err(CryptoError::InvalidKey)
                    }
                },
            )
            .map_err(|_| SymmetricKeyEnvelopeError::WrongKey)?;

        // Reconstruct the encoded symmetric key from the content format
        let encoded_key = match content_format {
            ContentFormat::BitwardenLegacyKey => {
                EncodedSymmetricKey::BitwardenLegacyKey(BitwardenLegacyKeyBytes::from(key_bytes))
            }
            ContentFormat::CoseKey => EncodedSymmetricKey::CoseKey(CoseKeyBytes::from(key_bytes)),
            _ => {
                return Err(SymmetricKeyEnvelopeError::WrongKeyType);
            }
        };

        SymmetricCryptoKey::try_from(encoded_key)
            .map_err(|_| SymmetricKeyEnvelopeError::WrongKeyType)
    }
}

fn build_cose_encrypt0_header(
    key_to_seal: &SymmetricCryptoKey,
    namespace: SymmetricKeyEnvelopeNamespace,
) -> (Header, Vec<u8>) {
    // set up headers
    let (content_format, key_bytes) = match key_to_seal.to_encoded_raw() {
        EncodedSymmetricKey::BitwardenLegacyKey(key_bytes) => {
            (ContentFormat::BitwardenLegacyKey, key_bytes.to_vec())
        }
        EncodedSymmetricKey::CoseKey(key_bytes) => (ContentFormat::CoseKey, key_bytes.to_vec()),
    };

    let mut header_builder = HeaderBuilder::from(content_format);

    // Only set the contained key ID if the key has one
    if let Some(key_id) = key_to_seal.key_id() {
        header_builder = header_builder.value(CONTAINED_KEY_ID, Value::from(Vec::from(&key_id)));
    }

    let mut header = header_builder.build();
    set_safe_namespaces(
        &mut header,
        SafeObjectNamespace::SymmetricKeyEnvelope,
        namespace,
    );
    (header, key_bytes)
}
