//! COSE symmetric encryption — the middle layer of the three-layer stack:
//! - Lowest: Hazmat primitive (`crate::hazmat::symmetric_encryption`)
//! - Mid: COSE framing (this module)
//! - High: Consumer (`crate::safe`, `EncString`)

use coset::{
    Algorithm, CborSerializable, CoseEncrypt, CoseEncrypt0, CoseEncrypt0Builder, CoseEncryptBuilder,
    Header, HeaderBuilder, iana,
};

use super::XCHACHA20_POLY1305;
use crate::{
    ContentFormat, CoseEncrypt0Bytes, CryptoError, XChaCha20Poly1305Key,
    error::EncStringParseError,
    hazmat::symmetric_encryption::{
        Aead,
        aes_gcm::{Aes256Gcm, Aes256GcmCiphertext, Aes256GcmNonce},
        xchacha20::{XChaCha20Poly1305, XChaCha20Poly1305Ciphertext, XChaCha20Poly1305Nonce},
    },
};

const TEXT_PAD_BLOCK_SIZE: usize = 32;

fn should_pad_content(format: &ContentFormat) -> bool {
    matches!(format, ContentFormat::Utf8)
}

/// The content-encryption algorithms that can seal the body of a COSE message.
///
/// This selects which [`CoseEncryptCipher`] the free `encrypt_cose`/`encrypt_cose0` functions
/// dispatch to. On decryption the algorithm is instead recovered from the message's protected
/// header (see [`decrypt_cose`]/[`decrypt_cose0`]), so the caller does not need to know it up
/// front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoseContentEncryptionAlgorithm {
    /// AES-256-GCM (COSE `A256GCM`).
    Aes256Gcm,
    /// XChaCha20-Poly1305 (private-use [`XCHACHA20_POLY1305`]).
    XChaCha20Poly1305,
}

impl TryFrom<&Algorithm> for CoseContentEncryptionAlgorithm {
    type Error = CryptoError;

    fn try_from(algorithm: &Algorithm) -> Result<Self, Self::Error> {
        match algorithm {
            Algorithm::Assigned(iana::Algorithm::A256GCM) => Ok(Self::Aes256Gcm),
            Algorithm::PrivateUse(XCHACHA20_POLY1305) => Ok(Self::XChaCha20Poly1305),
            _ => Err(CryptoError::WrongKeyType),
        }
    }
}

/// Recovers the content-encryption algorithm declared in a message's protected header, falling back
/// to `default_algorithm` when the header omits one.
///
/// Some legacy envelopes (notably early
/// [`PasswordProtectedKeyEnvelope`](crate::safe::PasswordProtectedKeyEnvelope)s) were sealed
/// without declaring the content-encryption algorithm in their protected header. Callers
/// that must decrypt such messages pass the algorithm they expect as `default_algorithm`; passing
/// `None` requires the header to declare it.
fn algorithm_from_header(
    header: &Header,
    default_algorithm: Option<CoseContentEncryptionAlgorithm>,
) -> Result<CoseContentEncryptionAlgorithm, CryptoError> {
    match header.alg.as_ref() {
        Some(algorithm) => CoseContentEncryptionAlgorithm::try_from(algorithm),
        None => default_algorithm.ok_or(CryptoError::EncString(
            EncStringParseError::CoseMissingAlgorithm,
        )),
    }
}

/// Validates that, if the protected `header` declares a content-encryption algorithm, it matches
/// `C`'s.
///
/// A missing algorithm is tolerated to support legacy envelopes that were sealed without declaring
/// it; in that case the dispatcher has already selected the cipher via its fallback. A
/// present-but-wrong algorithm is rejected with [`CryptoError::WrongKeyType`].
fn ensure_algorithm_matches<C: CoseEncryptCipher>(header: &Header) -> Result<(), CryptoError> {
    match header.alg.as_ref() {
        Some(algorithm) if algorithm != &C::COSE_ALGORITHM => Err(CryptoError::WrongKeyType),
        _ => Ok(()),
    }
}

/// Encrypts `plaintext` into a multi-recipient COSE [`CoseEncrypt`] message, dispatching to the
/// [`CoseEncryptCipher`] selected by `algorithm`.
///
/// The chosen cipher declares its algorithm in the (authenticated) protected header, so
/// [`decrypt_cose`] can recover it from the message without the caller specifying it. The caller is
/// expected to have configured the recipient(s) on `builder`; `cek` is the content-encryption key
/// and must match the selected cipher's key length.
///
/// If the `protected_header` declares a [`ContentFormat::Utf8`] content type, the plaintext is
/// padded to a block boundary before encryption to hide its exact length. The corresponding
/// [`decrypt_cose`] removes the padding transparently.
pub(crate) fn encrypt_cose(
    algorithm: CoseContentEncryptionAlgorithm,
    builder: CoseEncryptBuilder,
    protected_header: Header,
    plaintext: &[u8],
    cek: &[u8],
) -> Result<CoseEncrypt, CryptoError> {
    let mut plaintext = plaintext.to_vec();
    if let Ok(content_format) = ContentFormat::try_from(&protected_header) {
        if should_pad_content(&content_format) {
            let min_length =
                TEXT_PAD_BLOCK_SIZE * (1 + (plaintext.len() / TEXT_PAD_BLOCK_SIZE));
            crate::keys::utils::pad_bytes(&mut plaintext, min_length)?;
        }
    }
    match algorithm {
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let cek: &<Aes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(Aes256Gcm::encrypt_cose(
                builder,
                protected_header,
                &plaintext,
                cek,
            ))
        }
        CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
            let cek: &<XChaCha20Poly1305 as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(XChaCha20Poly1305::encrypt_cose(
                builder,
                protected_header,
                &plaintext,
                cek,
            ))
        }
    }
}

/// Authenticates and decrypts a multi-recipient COSE [`CoseEncrypt`] message, dispatching to the
/// [`CoseEncryptCipher`] indicated by the content-encryption algorithm declared in the message's
/// protected header.
///
/// When the protected header omits the content-encryption algorithm (some legacy envelopes),
/// `default_algorithm` is used instead; pass `None` to require the header to declare it.
///
/// Returns an error if the algorithm cannot be determined or is unsupported, if `cek` has the wrong
/// length for that cipher, or if authentication fails.
pub(crate) fn decrypt_cose(
    cose_encrypt: &CoseEncrypt,
    default_algorithm: Option<CoseContentEncryptionAlgorithm>,
    cek: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let decrypted = match algorithm_from_header(&cose_encrypt.protected.header, default_algorithm)?
    {
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let cek: &<Aes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Aes256Gcm::decrypt_cose(cose_encrypt, cek)?
        }
        CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
            let cek: &<XChaCha20Poly1305 as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            XChaCha20Poly1305::decrypt_cose(cose_encrypt, cek)?
        }
    };
    if let Ok(content_format) = ContentFormat::try_from(&cose_encrypt.protected.header) {
        if should_pad_content(&content_format) {
            return Ok(crate::keys::utils::unpad_bytes(&decrypted)?.to_vec());
        }
    }
    Ok(decrypted)
}

/// Encrypts `plaintext` into a single-recipient COSE [`CoseEncrypt0`] message, dispatching to the
/// [`CoseEncryptCipher`] selected by `algorithm`.
///
/// As with [`encrypt_cose`], the cipher declares its algorithm in the (authenticated) protected
/// header so [`decrypt_cose0`] can recover it. `cek` is the content-encryption key and must match
/// the selected cipher's key length. Padding is applied for [`ContentFormat::Utf8`] content.
pub(crate) fn encrypt_cose0(
    algorithm: CoseContentEncryptionAlgorithm,
    builder: CoseEncrypt0Builder,
    protected_header: Header,
    plaintext: &[u8],
    cek: &[u8],
) -> Result<CoseEncrypt0, CryptoError> {
    let mut plaintext = plaintext.to_vec();
    if let Ok(content_format) = ContentFormat::try_from(&protected_header) {
        if should_pad_content(&content_format) {
            let min_length =
                TEXT_PAD_BLOCK_SIZE * (1 + (plaintext.len() / TEXT_PAD_BLOCK_SIZE));
            crate::keys::utils::pad_bytes(&mut plaintext, min_length)?;
        }
    }
    match algorithm {
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let cek: &<Aes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(Aes256Gcm::encrypt_cose0(
                builder,
                protected_header,
                &plaintext,
                cek,
            ))
        }
        CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
            let cek: &<XChaCha20Poly1305 as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(XChaCha20Poly1305::encrypt_cose0(
                builder,
                protected_header,
                &plaintext,
                cek,
            ))
        }
    }
}

/// Authenticates and decrypts a single-recipient COSE [`CoseEncrypt0`] message, dispatching to the
/// [`CoseEncryptCipher`] indicated by the content-encryption algorithm declared in the message's
/// protected header.
///
/// When the protected header omits the content-encryption algorithm (some legacy envelopes),
/// `default_algorithm` is used instead; pass `None` to require the header to declare it.
///
/// Returns an error if the algorithm cannot be determined or is unsupported, if `cek` has the wrong
/// length for that cipher, or if authentication fails.
pub(crate) fn decrypt_cose0(
    cose_encrypt0: &CoseEncrypt0,
    default_algorithm: Option<CoseContentEncryptionAlgorithm>,
    cek: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let decrypted =
        match algorithm_from_header(&cose_encrypt0.protected.header, default_algorithm)? {
            CoseContentEncryptionAlgorithm::Aes256Gcm => {
                let cek: &<Aes256Gcm as Aead>::Key =
                    cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
                Aes256Gcm::decrypt_cose0(cose_encrypt0, cek)?
            }
            CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
                let cek: &<XChaCha20Poly1305 as Aead>::Key =
                    cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
                XChaCha20Poly1305::decrypt_cose0(cose_encrypt0, cek)?
            }
        };
    if let Ok(content_format) = ContentFormat::try_from(&cose_encrypt0.protected.header) {
        if should_pad_content(&content_format) {
            return Ok(crate::keys::utils::unpad_bytes(&decrypted)?.to_vec());
        }
    }
    Ok(decrypted)
}

/// Encrypts and decrypts the content of COSE [`CoseEncrypt`]/[`CoseEncrypt0`] messages with an
/// [`Aead`] cipher, using the cipher's key as the content-encryption key (CEK).
pub(crate) trait CoseEncryptCipher: Aead {
    /// The COSE algorithm identifier for this content-encryption cipher. It is written to the
    /// protected header by the `encrypt_*` methods and validated by the `decrypt_*` methods.
    const COSE_ALGORITHM: Algorithm;

    /// Encrypts `plaintext` under `cek` into a [`CoseEncrypt`], declaring
    /// [`COSE_ALGORITHM`](Self::COSE_ALGORITHM) in the (authenticated) protected header and storing
    /// the freshly generated nonce in the unprotected `iv` header.
    ///
    /// The caller is expected to have already configured the recipient(s) on the builder. A fresh
    /// random nonce is generated on every call; combined with a per-message CEK this avoids nonce
    /// reuse.
    fn encrypt_cose(
        builder: CoseEncryptBuilder,
        protected_header: Header,
        plaintext: &[u8],
        cek: &Self::Key,
    ) -> CoseEncrypt;

    /// Authenticates and decrypts the ciphertext of `cose_encrypt` under `cek`, reading the nonce
    /// from the unprotected `iv` header.
    ///
    /// Returns an error if the protected header does not declare
    /// [`COSE_ALGORITHM`](Self::COSE_ALGORITHM), the `iv` header is missing or malformed, the
    /// ciphertext is missing, or authentication fails (wrong key, tampered ciphertext, or wrong
    /// associated data).
    fn decrypt_cose(cose_encrypt: &CoseEncrypt, cek: &Self::Key) -> Result<Vec<u8>, CryptoError>;

    /// Encrypts `plaintext` under `cek` into a [`CoseEncrypt0`]. Behaves like
    /// [`encrypt_cose`](Self::encrypt_cose), but produces a single-recipient message.
    fn encrypt_cose0(
        builder: CoseEncrypt0Builder,
        protected_header: Header,
        plaintext: &[u8],
        cek: &Self::Key,
    ) -> CoseEncrypt0;

    /// Authenticates and decrypts the ciphertext of `cose_encrypt0` under `cek`. Behaves like
    /// [`decrypt_cose`](Self::decrypt_cose), but for a single-recipient message.
    fn decrypt_cose0(cose_encrypt0: &CoseEncrypt0, cek: &Self::Key)
    -> Result<Vec<u8>, CryptoError>;
}

impl CoseEncryptCipher for Aes256Gcm {
    const COSE_ALGORITHM: Algorithm = Algorithm::Assigned(iana::Algorithm::A256GCM);

    fn encrypt_cose(
        builder: CoseEncryptBuilder,
        mut protected_header: Header,
        plaintext: &[u8],
        cek: &Self::Key,
    ) -> CoseEncrypt {
        // Declare the content-encryption algorithm in the protected header so it is authenticated
        // as part of the AEAD's associated data, and so the COSE object is self-describing.
        protected_header.alg = Some(Self::COSE_ALGORITHM);

        // AES-256-GCM requires a fresh nonce per message. The CEK is locally derived and unique per
        // message, so a fresh random nonce is generated regardless. The nonce is stored in the
        // unprotected `iv` header via the builder.
        let nonce = Aes256GcmNonce::make();
        builder
            .protected(protected_header)
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(plaintext, &[], |data, aad| {
                Aes256Gcm::encrypt(cek, &nonce, data, aad)
                    .encrypted_bytes()
                    .to_vec()
            })
            .build()
    }

    fn decrypt_cose(cose_encrypt: &CoseEncrypt, cek: &Self::Key) -> Result<Vec<u8>, CryptoError> {
        // If the protected header declares an algorithm it must be this cipher's; a missing
        // algorithm is tolerated for legacy envelopes (the dispatcher selected the cipher). The
        // header is authenticated as part of the AEAD associated data regardless.
        ensure_algorithm_matches::<Self>(&cose_encrypt.protected.header)?;

        let nonce = Aes256GcmNonce::try_from(cose_encrypt)?;
        cose_encrypt.decrypt_ciphertext(
            &[],
            || CryptoError::MissingField("ciphertext"),
            |data, aad| {
                Aes256Gcm::decrypt(cek, &nonce, &Aes256GcmCiphertext::from(data.to_vec()), aad)
            },
        )
    }

    fn encrypt_cose0(
        builder: CoseEncrypt0Builder,
        mut protected_header: Header,
        plaintext: &[u8],
        cek: &Self::Key,
    ) -> CoseEncrypt0 {
        protected_header.alg = Some(Self::COSE_ALGORITHM);

        let nonce = Aes256GcmNonce::make();
        builder
            .protected(protected_header)
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(plaintext, &[], |data, aad| {
                Aes256Gcm::encrypt(cek, &nonce, data, aad)
                    .encrypted_bytes()
                    .to_vec()
            })
            .build()
    }

    fn decrypt_cose0(
        cose_encrypt0: &CoseEncrypt0,
        cek: &Self::Key,
    ) -> Result<Vec<u8>, CryptoError> {
        ensure_algorithm_matches::<Self>(&cose_encrypt0.protected.header)?;

        let nonce = Aes256GcmNonce::try_from(cose_encrypt0)?;
        cose_encrypt0.decrypt_ciphertext(
            &[],
            || CryptoError::MissingField("ciphertext"),
            |data, aad| {
                Aes256Gcm::decrypt(cek, &nonce, &Aes256GcmCiphertext::from(data.to_vec()), aad)
            },
        )
    }
}

impl CoseEncryptCipher for XChaCha20Poly1305 {
    const COSE_ALGORITHM: Algorithm = Algorithm::PrivateUse(XCHACHA20_POLY1305);

    fn encrypt_cose(
        builder: CoseEncryptBuilder,
        mut protected_header: Header,
        plaintext: &[u8],
        cek: &Self::Key,
    ) -> CoseEncrypt {
        protected_header.alg = Some(Self::COSE_ALGORITHM);

        let nonce = XChaCha20Poly1305Nonce::make();
        builder
            .protected(protected_header)
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(plaintext, &[], |data, aad| {
                XChaCha20Poly1305::encrypt(cek, &nonce, data, aad)
                    .encrypted_bytes()
                    .to_vec()
            })
            .build()
    }

    fn decrypt_cose(cose_encrypt: &CoseEncrypt, cek: &Self::Key) -> Result<Vec<u8>, CryptoError> {
        ensure_algorithm_matches::<Self>(&cose_encrypt.protected.header)?;

        let nonce = XChaCha20Poly1305Nonce::try_from(cose_encrypt)?;
        cose_encrypt.decrypt_ciphertext(
            &[],
            || CryptoError::MissingField("ciphertext"),
            |data, aad| {
                XChaCha20Poly1305::decrypt(
                    cek,
                    &nonce,
                    &XChaCha20Poly1305Ciphertext::from(data.to_vec()),
                    aad,
                )
            },
        )
    }

    fn encrypt_cose0(
        builder: CoseEncrypt0Builder,
        mut protected_header: Header,
        plaintext: &[u8],
        cek: &Self::Key,
    ) -> CoseEncrypt0 {
        protected_header.alg = Some(Self::COSE_ALGORITHM);

        let nonce = XChaCha20Poly1305Nonce::make();
        builder
            .protected(protected_header)
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(plaintext, &[], |data, aad| {
                XChaCha20Poly1305::encrypt(cek, &nonce, data, aad)
                    .encrypted_bytes()
                    .to_vec()
            })
            .build()
    }

    fn decrypt_cose0(
        cose_encrypt0: &CoseEncrypt0,
        cek: &Self::Key,
    ) -> Result<Vec<u8>, CryptoError> {
        ensure_algorithm_matches::<Self>(&cose_encrypt0.protected.header)?;

        let nonce = XChaCha20Poly1305Nonce::try_from(cose_encrypt0)?;
        cose_encrypt0.decrypt_ciphertext(
            &[],
            || CryptoError::MissingField("ciphertext"),
            |data, aad| {
                XChaCha20Poly1305::decrypt(
                    cek,
                    &nonce,
                    &XChaCha20Poly1305Ciphertext::from(data.to_vec()),
                    aad,
                )
            },
        )
    }
}

/// Encrypts a plaintext message using XChaCha20Poly1305 and returns a COSE Encrypt0 message.
pub(crate) fn encrypt_xchacha20_poly1305(
    plaintext: &[u8],
    key: &XChaCha20Poly1305Key,
    content_format: ContentFormat,
) -> Result<CoseEncrypt0Bytes, CryptoError> {
    let mut plaintext = plaintext.to_vec();

    let header_builder: coset::HeaderBuilder = content_format.into();
    let mut protected_header = header_builder
        .key_id(key.key_id.as_slice().to_vec())
        .build();
    // This should be adjusted to use the builder pattern once implemented in coset.
    // The related coset upstream issue is:
    // https://github.com/google/coset/issues/105
    protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));

    if should_pad_content(&content_format) {
        let min_length =
            TEXT_PAD_BLOCK_SIZE * (1 + (plaintext.len() / TEXT_PAD_BLOCK_SIZE));
        crate::keys::utils::pad_bytes(&mut plaintext, min_length)?;
    }

    let nonce = XChaCha20Poly1305Nonce::make();
    let cose_encrypt0 = coset::CoseEncrypt0Builder::new()
        .protected(protected_header)
        .create_ciphertext(&plaintext, &[], |data, aad| {
            XChaCha20Poly1305::encrypt(&(*key.enc_key).into(), &nonce, data, aad)
                .encrypted_bytes()
                .to_vec()
        })
        .unprotected(
            coset::HeaderBuilder::new()
                .iv(nonce.as_bytes().to_vec())
                .build(),
        )
        .build();

    cose_encrypt0
        .to_vec()
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))
        .map(CoseEncrypt0Bytes::from)
}

/// Decrypts a COSE Encrypt0 message using a XChaCha20Poly1305 key.
pub(crate) fn decrypt_xchacha20_poly1305(
    cose_encrypt0_message: &CoseEncrypt0Bytes,
    key: &XChaCha20Poly1305Key,
) -> Result<(Vec<u8>, ContentFormat), CryptoError> {
    let msg = coset::CoseEncrypt0::from_slice(cose_encrypt0_message.as_ref())
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))?;

    let Some(ref alg) = msg.protected.header.alg else {
        return Err(CryptoError::EncString(
            EncStringParseError::CoseMissingAlgorithm,
        ));
    };

    if *alg != coset::Algorithm::PrivateUse(XCHACHA20_POLY1305) {
        return Err(CryptoError::WrongKeyType);
    }

    let content_format = ContentFormat::try_from(&msg.protected.header)
        .map_err(|_| CryptoError::EncString(EncStringParseError::CoseMissingContentType))?;

    if key.key_id.as_slice() != msg.protected.header.key_id {
        return Err(CryptoError::WrongCoseKeyId);
    }

    let nonce = XChaCha20Poly1305Nonce::try_from(&msg)?;
    let decrypted_message = msg.decrypt_ciphertext(
        &[],
        || CryptoError::MissingField("ciphertext"),
        |data, aad| {
            XChaCha20Poly1305::decrypt(
                &(*key.enc_key).into(),
                &nonce,
                &XChaCha20Poly1305Ciphertext::from(data.to_vec()),
                aad,
            )
        },
    )?;

    if should_pad_content(&content_format) {
        let data = crate::keys::utils::unpad_bytes(&decrypted_message)?;
        return Ok((data.to_vec(), content_format));
    }

    Ok((decrypted_message, content_format))
}

#[cfg(test)]
mod tests {
    use coset::{CoseEncrypt0Builder, CoseEncryptBuilder, CoseRecipientBuilder, HeaderBuilder};
    use hybrid_array::Array;
    use iana::KeyOperation;

    use super::*;
    use crate::keys::KeyId;

    const CEK: [u8; 32] = [7u8; 32];
    const PLAINTEXT: &[u8] = b"content-encryption test vector";

    const KEY_ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const KEY_DATA: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const TEST_VECTOR_PLAINTEXT: &[u8] = b"Message test vector";
    const TEST_VECTOR_COSE_ENCRYPT0: &[u8] = &[
        131, 88, 28, 163, 1, 58, 0, 1, 17, 111, 3, 24, 42, 4, 80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 161, 5, 88, 24, 78, 20, 28, 157, 180, 246, 131, 220, 82, 104, 72,
        73, 75, 43, 69, 139, 216, 167, 145, 220, 67, 168, 144, 173, 88, 35, 127, 234, 194, 83,
        189, 172, 65, 29, 156, 73, 98, 87, 231, 87, 129, 15, 235, 127, 125, 97, 211, 51, 212, 211,
        2, 13, 36, 123, 53, 12, 31, 191, 40, 13, 175,
    ];

    fn algorithms() -> [CoseContentEncryptionAlgorithm; 2] {
        [
            CoseContentEncryptionAlgorithm::Aes256Gcm,
            CoseContentEncryptionAlgorithm::XChaCha20Poly1305,
        ]
    }

    fn make_xchacha_key() -> XChaCha20Poly1305Key {
        XChaCha20Poly1305Key {
            key_id: KeyId::from(KEY_ID),
            enc_key: Box::pin(Array::from(KEY_DATA)),
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        }
    }

    #[test]
    fn test_encrypt_decrypt_cose_roundtrip() {
        for algorithm in algorithms() {
            let builder =
                CoseEncryptBuilder::new().add_recipient(CoseRecipientBuilder::new().build());
            let cose_encrypt = encrypt_cose(
                algorithm,
                builder,
                HeaderBuilder::new().build(),
                PLAINTEXT,
                &CEK,
            )
            .unwrap();
            let decrypted = decrypt_cose(&cose_encrypt, None, &CEK).unwrap();
            assert_eq!(decrypted, PLAINTEXT);
        }
    }

    #[test]
    fn test_encrypt_decrypt_cose0_roundtrip() {
        for algorithm in algorithms() {
            let cose_encrypt0 = encrypt_cose0(
                algorithm,
                CoseEncrypt0Builder::new(),
                HeaderBuilder::new().build(),
                PLAINTEXT,
                &CEK,
            )
            .unwrap();
            let decrypted = decrypt_cose0(&cose_encrypt0, None, &CEK).unwrap();
            assert_eq!(decrypted, PLAINTEXT);
        }
    }

    #[test]
    fn test_decrypt_cose0_wrong_key_fails() {
        let cose_encrypt0 = encrypt_cose0(
            CoseContentEncryptionAlgorithm::XChaCha20Poly1305,
            CoseEncrypt0Builder::new(),
            HeaderBuilder::new().build(),
            PLAINTEXT,
            &CEK,
        )
        .unwrap();
        let wrong_cek = [0u8; 32];
        assert!(decrypt_cose0(&cose_encrypt0, None, &wrong_cek).is_err());
    }

    #[test]
    fn test_decrypt_cose0_missing_algorithm_fails_without_default() {
        // A message with no declared algorithm and no fallback cannot be dispatched.
        let cose_encrypt0 = CoseEncrypt0Builder::new()
            .protected(HeaderBuilder::new().build())
            .create_ciphertext(PLAINTEXT, &[], |data, _| data.to_vec())
            .build();
        assert!(matches!(
            decrypt_cose0(&cose_encrypt0, None, &CEK),
            Err(CryptoError::EncString(
                EncStringParseError::CoseMissingAlgorithm
            ))
        ));
    }

    #[test]
    fn test_decrypt_cose0_missing_algorithm_uses_default() {
        // A legacy message with no declared algorithm decrypts when a fallback algorithm is
        // provided. This is built by hand to omit the algorithm from the protected header, which
        // the `encrypt_cose0` helper would otherwise always set.
        let nonce = XChaCha20Poly1305Nonce::make();
        let cose_encrypt0 = CoseEncrypt0Builder::new()
            .protected(HeaderBuilder::new().build())
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(PLAINTEXT, &[], |data, aad| {
                XChaCha20Poly1305::encrypt(&CEK, &nonce, data, aad)
                    .encrypted_bytes()
                    .to_vec()
            })
            .build();

        let decrypted = decrypt_cose0(
            &cose_encrypt0,
            Some(CoseContentEncryptionAlgorithm::XChaCha20Poly1305),
            &CEK,
        )
        .unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }

    #[test]
    fn test_encrypt_decrypt_xchacha20_roundtrip_octetstream() {
        use crate::SymmetricCryptoKey;
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted =
            encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::OctetStream).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::OctetStream));
    }

    #[test]
    fn test_encrypt_decrypt_xchacha20_roundtrip_utf8() {
        use crate::SymmetricCryptoKey;
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted = encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::Utf8).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::Utf8));
    }

    #[test]
    fn test_encrypt_decrypt_xchacha20_roundtrip_pkcs8() {
        use crate::SymmetricCryptoKey;
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted =
            encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::Pkcs8PrivateKey).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(
            decrypted,
            (plaintext.to_vec(), ContentFormat::Pkcs8PrivateKey)
        );
    }

    #[test]
    fn test_encrypt_decrypt_xchacha20_roundtrip_cosekey() {
        use crate::SymmetricCryptoKey;
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted =
            encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::CoseKey).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::CoseKey));
    }

    #[test]
    fn test_decrypt_xchacha20_test_vector() {
        let key = make_xchacha_key();
        let decrypted =
            decrypt_xchacha20_poly1305(&CoseEncrypt0Bytes::from(TEST_VECTOR_COSE_ENCRYPT0), &key)
                .unwrap();
        assert_eq!(
            decrypted,
            (TEST_VECTOR_PLAINTEXT.to_vec(), ContentFormat::OctetStream)
        );
    }

    #[test]
    fn test_decrypt_xchacha20_fail_wrong_key_id() {
        let key = XChaCha20Poly1305Key {
            key_id: KeyId::from([1; 16]),
            enc_key: Box::pin(Array::from(KEY_DATA)),
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        };
        assert!(matches!(
            decrypt_xchacha20_poly1305(&CoseEncrypt0Bytes::from(TEST_VECTOR_COSE_ENCRYPT0), &key),
            Err(CryptoError::WrongCoseKeyId)
        ));
    }

    #[test]
    fn test_decrypt_xchacha20_fail_wrong_algorithm() {
        use coset::iana;
        let protected_header = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::A256GCM)
            .key_id(KEY_ID.to_vec())
            .build();
        let nonce = [0u8; 16];
        let cose_encrypt0 = coset::CoseEncrypt0Builder::new()
            .protected(protected_header)
            .create_ciphertext(&[], &[], |_, _| Vec::new())
            .unprotected(coset::HeaderBuilder::new().iv(nonce.to_vec()).build())
            .build();
        let serialized_message =
            CoseEncrypt0Bytes::from(cose_encrypt0.to_vec().unwrap());

        let key = make_xchacha_key();
        assert!(matches!(
            decrypt_xchacha20_poly1305(&serialized_message, &key),
            Err(CryptoError::WrongKeyType)
        ));
    }
}
