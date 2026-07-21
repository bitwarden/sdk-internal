//! COSE symmetric encryption — the middle layer of the three-layer stack:
//! - Lowest: Hazmat primitive (`crate::hazmat::symmetric_encryption`)
//! - Mid: COSE framing (this module)
//! - High: Consumer (`crate::safe`, `EncString`)

use coset::{
    Algorithm, CborSerializable, CoseEncrypt, CoseEncrypt0, CoseEncrypt0Builder,
    CoseEncryptBuilder, Header, HeaderBuilder, iana,
};

use super::{AES256_CBC_HMAC_SHA256, XAES_256_GCM, XCHACHA20_POLY1305};
use crate::{
    Aes256CbcHmacKey, ContentFormat, CoseEncrypt0Bytes, CryptoError, XAes256GcmKey,
    XChaCha20Poly1305Key,
    error::EncStringParseError,
    hazmat::symmetric_encryption::{
        Aead,
        aes_gcm::{Aes256Gcm, Aes256GcmCiphertext, Aes256GcmNonce},
        aes256_cbc_hmac_sha256_aead::{
            Aes256CbcHmacSha256Aead, Aes256CbcHmacSha256AeadCiphertext,
            Aes256CbcHmacSha256AeadNonce,
        },
        xaes_256_gcm::{XAes256Gcm, XAes256GcmCiphertext, XAes256GcmNonce},
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
/// dispatch to. On decryption, [`CoseAlgorithmPolicy`] determines whether the protected algorithm
/// is required, must match an independently typed CEK, or may be replaced by a legacy default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoseContentEncryptionAlgorithm {
    /// AES-256-GCM (COSE `A256GCM`).
    Aes256Gcm,
    /// XAES-256-GCM (private-use [`XAES_256_GCM`]).
    XAes256Gcm,
    /// XChaCha20-Poly1305 (private-use [`XCHACHA20_POLY1305`]).
    XChaCha20Poly1305,
    /// AES-256-CBC-HMAC-SHA256 (private-use [`AES256_CBC_HMAC_SHA256`]).
    Aes256CbcHmacSha256,
}

/// Policy for resolving and validating a COSE message's content-encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoseAlgorithmPolicy {
    /// Require a supported algorithm in the protected header.
    RequireProtectedHeaderAlgorithm,
    /// Require the protected algorithm to exactly match the independently known CEK algorithm.
    Exactly(CoseContentEncryptionAlgorithm),
    /// Use the protected algorithm when present, or the supplied default for a legacy message.
    ProtectedHeaderAlgorithmOrLegacyDefault(CoseContentEncryptionAlgorithm),
}

impl TryFrom<&Algorithm> for CoseContentEncryptionAlgorithm {
    type Error = CryptoError;

    fn try_from(algorithm: &Algorithm) -> Result<Self, Self::Error> {
        match algorithm {
            Algorithm::Assigned(iana::Algorithm::A256GCM) => Ok(Self::Aes256Gcm),
            Algorithm::PrivateUse(XAES_256_GCM) => Ok(Self::XAes256Gcm),
            Algorithm::PrivateUse(XCHACHA20_POLY1305) => Ok(Self::XChaCha20Poly1305),
            Algorithm::PrivateUse(AES256_CBC_HMAC_SHA256) => Ok(Self::Aes256CbcHmacSha256),
            _ => Err(CryptoError::WrongKeyType),
        }
    }
}

/// Resolves the content-encryption algorithm according to `policy`.
///
/// Some legacy envelopes
/// (notably early [`PasswordProtectedKeyEnvelope`](crate::safe::PasswordProtectedKeyEnvelope)s)
/// were sealed without declaring the content-encryption algorithm in their protected header.
/// Only the legacy-default policy permits a missing protected algorithm. An exact policy rejects a
/// supported but different algorithm before the CEK is converted or used.
fn algorithm_from_header(
    header: &Header,
    policy: CoseAlgorithmPolicy,
) -> Result<CoseContentEncryptionAlgorithm, CryptoError> {
    let declared = header
        .alg
        .as_ref()
        .map(CoseContentEncryptionAlgorithm::try_from)
        .transpose()?;

    match (policy, declared) {
        (CoseAlgorithmPolicy::ProtectedHeaderAlgorithmOrLegacyDefault(default), None) => {
            Ok(default)
        }
        (_, None) => Err(CryptoError::EncString(
            EncStringParseError::CoseMissingAlgorithm,
        )),
        (CoseAlgorithmPolicy::Exactly(expected), Some(actual)) if actual != expected => {
            Err(CryptoError::WrongKeyType)
        }
        (_, Some(actual)) => Ok(actual),
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
    if let Ok(content_format) = ContentFormat::try_from(&protected_header)
        && should_pad_content(&content_format)
    {
        let min_length = TEXT_PAD_BLOCK_SIZE * (1 + (plaintext.len() / TEXT_PAD_BLOCK_SIZE));
        crate::keys::utils::pad_bytes(&mut plaintext, min_length)?;
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
        CoseContentEncryptionAlgorithm::XAes256Gcm => {
            let cek: &<XAes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(XAes256Gcm::encrypt_cose(
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
        CoseContentEncryptionAlgorithm::Aes256CbcHmacSha256 => {
            let cek: &<Aes256CbcHmacSha256Aead as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(Aes256CbcHmacSha256Aead::encrypt_cose(
                builder,
                protected_header,
                &plaintext,
                cek,
            ))
        }
    }
}

/// Authenticates and decrypts a multi-recipient COSE [`CoseEncrypt`] message.
///
/// `policy` controls whether the protected algorithm is required, must exactly match a typed CEK,
/// or may fall back only for a legacy message. Returns an error for a missing, unsupported, or
/// policy-mismatched algorithm, an invalid CEK length, or failed authentication.
pub(crate) fn decrypt_cose(
    cose_encrypt: &CoseEncrypt,
    policy: CoseAlgorithmPolicy,
    cek: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let decrypted = match algorithm_from_header(&cose_encrypt.protected.header, policy)? {
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let cek: &<Aes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Aes256Gcm::decrypt_cose(cose_encrypt, cek)?
        }
        CoseContentEncryptionAlgorithm::XAes256Gcm => {
            let cek: &<XAes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            XAes256Gcm::decrypt_cose(cose_encrypt, cek)?
        }
        CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
            let cek: &<XChaCha20Poly1305 as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            XChaCha20Poly1305::decrypt_cose(cose_encrypt, cek)?
        }
        CoseContentEncryptionAlgorithm::Aes256CbcHmacSha256 => {
            let cek: &<Aes256CbcHmacSha256Aead as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Aes256CbcHmacSha256Aead::decrypt_cose(cose_encrypt, cek)?
        }
    };
    if let Ok(content_format) = ContentFormat::try_from(&cose_encrypt.protected.header)
        && should_pad_content(&content_format)
    {
        return Ok(crate::keys::utils::unpad_bytes(&decrypted)?.to_vec());
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
    if let Ok(content_format) = ContentFormat::try_from(&protected_header)
        && should_pad_content(&content_format)
    {
        let min_length = TEXT_PAD_BLOCK_SIZE * (1 + (plaintext.len() / TEXT_PAD_BLOCK_SIZE));
        crate::keys::utils::pad_bytes(&mut plaintext, min_length)?;
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
        CoseContentEncryptionAlgorithm::XAes256Gcm => {
            let cek: &<XAes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(XAes256Gcm::encrypt_cose0(
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
        CoseContentEncryptionAlgorithm::Aes256CbcHmacSha256 => {
            let cek: &<Aes256CbcHmacSha256Aead as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(Aes256CbcHmacSha256Aead::encrypt_cose0(
                builder,
                protected_header,
                &plaintext,
                cek,
            ))
        }
    }
}

/// Authenticates and decrypts a single-recipient COSE [`CoseEncrypt0`] message.
///
/// `policy` controls whether the protected algorithm is required, must exactly match a typed CEK,
/// or may fall back only for a legacy message. Returns an error for a missing, unsupported, or
/// policy-mismatched algorithm, an invalid CEK length, or failed authentication.
pub(crate) fn decrypt_cose0(
    cose_encrypt0: &CoseEncrypt0,
    policy: CoseAlgorithmPolicy,
    cek: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let decrypted = match algorithm_from_header(&cose_encrypt0.protected.header, policy)? {
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let cek: &<Aes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Aes256Gcm::decrypt_cose0(cose_encrypt0, cek)?
        }
        CoseContentEncryptionAlgorithm::XAes256Gcm => {
            let cek: &<XAes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            XAes256Gcm::decrypt_cose0(cose_encrypt0, cek)?
        }
        CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
            let cek: &<XChaCha20Poly1305 as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            XChaCha20Poly1305::decrypt_cose0(cose_encrypt0, cek)?
        }
        CoseContentEncryptionAlgorithm::Aes256CbcHmacSha256 => {
            let cek: &<Aes256CbcHmacSha256Aead as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Aes256CbcHmacSha256Aead::decrypt_cose0(cose_encrypt0, cek)?
        }
    };
    if let Ok(content_format) = ContentFormat::try_from(&cose_encrypt0.protected.header)
        && should_pad_content(&content_format)
    {
        return Ok(crate::keys::utils::unpad_bytes(&decrypted)?.to_vec());
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
    /// random nonce is generated on every call. Callers are required to use per-message keys or
    /// otherwise satisfy the selected algorithm's requirements to avoid nonce reuse.
    fn encrypt_cose(
        builder: CoseEncryptBuilder,
        protected_header: Header,
        plaintext: &[u8],
        cek: &Self::Key,
    ) -> CoseEncrypt;

    /// Authenticates and decrypts the ciphertext of `cose_encrypt` under `cek`, reading the nonce
    /// from the unprotected `iv` header.
    ///
    /// Returns an error if a present protected algorithm does not match
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

impl CoseEncryptCipher for XAes256Gcm {
    const COSE_ALGORITHM: Algorithm = Algorithm::PrivateUse(XAES_256_GCM);

    fn encrypt_cose(
        builder: CoseEncryptBuilder,
        mut protected_header: Header,
        plaintext: &[u8],
        cek: &Self::Key,
    ) -> CoseEncrypt {
        protected_header.alg = Some(Self::COSE_ALGORITHM);

        let nonce = XAes256GcmNonce::make();
        builder
            .protected(protected_header)
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(plaintext, &[], |data, aad| {
                XAes256Gcm::encrypt(cek, &nonce, data, aad)
                    .encrypted_bytes()
                    .to_vec()
            })
            .build()
    }

    fn decrypt_cose(cose_encrypt: &CoseEncrypt, cek: &Self::Key) -> Result<Vec<u8>, CryptoError> {
        ensure_algorithm_matches::<Self>(&cose_encrypt.protected.header)?;

        let nonce = XAes256GcmNonce::try_from(cose_encrypt)?;
        cose_encrypt.decrypt_ciphertext(
            &[],
            || CryptoError::MissingField("ciphertext"),
            |data, aad| {
                XAes256Gcm::decrypt(cek, &nonce, &XAes256GcmCiphertext::from(data.to_vec()), aad)
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

        let nonce = XAes256GcmNonce::make();
        builder
            .protected(protected_header)
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(plaintext, &[], |data, aad| {
                XAes256Gcm::encrypt(cek, &nonce, data, aad)
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

        let nonce = XAes256GcmNonce::try_from(cose_encrypt0)?;
        cose_encrypt0.decrypt_ciphertext(
            &[],
            || CryptoError::MissingField("ciphertext"),
            |data, aad| {
                XAes256Gcm::decrypt(cek, &nonce, &XAes256GcmCiphertext::from(data.to_vec()), aad)
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

impl CoseEncryptCipher for Aes256CbcHmacSha256Aead {
    const COSE_ALGORITHM: Algorithm = Algorithm::PrivateUse(AES256_CBC_HMAC_SHA256);

    fn encrypt_cose(
        builder: CoseEncryptBuilder,
        mut protected_header: Header,
        plaintext: &[u8],
        cek: &Self::Key,
    ) -> CoseEncrypt {
        protected_header.alg = Some(Self::COSE_ALGORITHM);

        let nonce = Aes256CbcHmacSha256AeadNonce::make();
        builder
            .protected(protected_header)
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(plaintext, &[], |data, aad| {
                Aes256CbcHmacSha256Aead::encrypt(cek, &nonce, data, aad)
                    .encrypted_bytes()
                    .to_vec()
            })
            .build()
    }

    fn decrypt_cose(cose_encrypt: &CoseEncrypt, cek: &Self::Key) -> Result<Vec<u8>, CryptoError> {
        ensure_algorithm_matches::<Self>(&cose_encrypt.protected.header)?;

        let nonce = Aes256CbcHmacSha256AeadNonce::try_from(cose_encrypt)?;
        cose_encrypt.decrypt_ciphertext(
            &[],
            || CryptoError::MissingField("ciphertext"),
            |data, aad| {
                Aes256CbcHmacSha256Aead::decrypt(
                    cek,
                    &nonce,
                    &Aes256CbcHmacSha256AeadCiphertext::from(data.to_vec()),
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

        let nonce = Aes256CbcHmacSha256AeadNonce::make();
        builder
            .protected(protected_header)
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(plaintext, &[], |data, aad| {
                Aes256CbcHmacSha256Aead::encrypt(cek, &nonce, data, aad)
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

        let nonce = Aes256CbcHmacSha256AeadNonce::try_from(cose_encrypt0)?;
        cose_encrypt0.decrypt_ciphertext(
            &[],
            || CryptoError::MissingField("ciphertext"),
            |data, aad| {
                Aes256CbcHmacSha256Aead::decrypt(
                    cek,
                    &nonce,
                    &Aes256CbcHmacSha256AeadCiphertext::from(data.to_vec()),
                    aad,
                )
            },
        )
    }
}

/// Decrypts a COSE Encrypt0 message sealed with an AES-256-CBC-HMAC-SHA256 content-encryption key.
///
/// The 64-byte composite key (`enc_key || mac_key`) of `key` is used as the CEK. The protected
/// header must declare the [`AES256_CBC_HMAC_SHA256`] algorithm.
pub(crate) fn decrypt_aes256_cbc_hmac_sha256(
    message: &CoseEncrypt0Bytes,
    key: &Aes256CbcHmacKey,
) -> Result<(Vec<u8>, ContentFormat), CryptoError> {
    let msg = CoseEncrypt0::from_slice(message.as_ref())
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))?;

    let content_format = ContentFormat::try_from(&msg.protected.header)
        .map_err(|_| CryptoError::EncString(EncStringParseError::CoseMissingContentType))?;

    let decrypted = decrypt_cose0(
        &msg,
        CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::Aes256CbcHmacSha256),
        &*key.to_composite_key(),
    )?;

    Ok((decrypted, content_format))
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
        let min_length = TEXT_PAD_BLOCK_SIZE * (1 + (plaintext.len() / TEXT_PAD_BLOCK_SIZE));
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

/// Encrypts plaintext with XAES-256-GCM and returns a typed COSE Encrypt0 message.
pub(crate) fn encrypt_xaes256_gcm(
    plaintext: &[u8],
    key: &XAes256GcmKey,
    content_format: ContentFormat,
) -> Result<CoseEncrypt0Bytes, CryptoError> {
    let mut plaintext = plaintext.to_vec();
    let mut protected_header: Header = HeaderBuilder::from(content_format)
        .key_id(key.key_id.as_slice().to_vec())
        .build();
    protected_header.alg = Some(Algorithm::PrivateUse(XAES_256_GCM));

    // GCM as a stream cipher does not have a block size. We want to hide exact
    // input plaintext length, and pad the plaintext size, if the input is a string.
    if should_pad_content(&content_format) {
        let min_length = TEXT_PAD_BLOCK_SIZE * (1 + (plaintext.len() / TEXT_PAD_BLOCK_SIZE));
        crate::keys::utils::pad_bytes(&mut plaintext, min_length)?;
    }

    let nonce = XAes256GcmNonce::make();
    CoseEncrypt0Builder::new()
        .protected(protected_header)
        .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
        .create_ciphertext(&plaintext, &[], |data, aad| {
            XAes256Gcm::encrypt(&(*key.enc_key).into(), &nonce, data, aad)
                .encrypted_bytes()
                .to_vec()
        })
        .build()
        .to_vec()
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))
        .map(CoseEncrypt0Bytes::from)
}

/// Decrypts a typed COSE Encrypt0 message with an XAES-256-GCM key.
pub(crate) fn decrypt_xaes256_gcm(
    message: &CoseEncrypt0Bytes,
    key: &XAes256GcmKey,
) -> Result<(Vec<u8>, ContentFormat), CryptoError> {
    let msg = CoseEncrypt0::from_slice(message.as_ref())
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))?;

    let Some(ref algorithm) = msg.protected.header.alg else {
        return Err(CryptoError::EncString(
            EncStringParseError::CoseMissingAlgorithm,
        ));
    };
    if *algorithm != Algorithm::PrivateUse(XAES_256_GCM) {
        return Err(CryptoError::WrongKeyType);
    }

    let content_format = ContentFormat::try_from(&msg.protected.header)
        .map_err(|_| CryptoError::EncString(EncStringParseError::CoseMissingContentType))?;
    if key.key_id.as_slice() != msg.protected.header.key_id {
        return Err(CryptoError::WrongCoseKeyId);
    }

    let nonce = XAes256GcmNonce::try_from(&msg)?;
    let decrypted = msg.decrypt_ciphertext(
        &[],
        || CryptoError::MissingField("ciphertext"),
        |data, aad| {
            XAes256Gcm::decrypt(
                &(*key.enc_key).into(),
                &nonce,
                &XAes256GcmCiphertext::from(data.to_vec()),
                aad,
            )
        },
    )?;

    if should_pad_content(&content_format) {
        return Ok((
            crate::keys::utils::unpad_bytes(&decrypted)?.to_vec(),
            content_format,
        ));
    }

    Ok((decrypted, content_format))
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
        131, 88, 28, 163, 1, 58, 0, 1, 17, 111, 3, 24, 42, 4, 80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 161, 5, 88, 24, 78, 20, 28, 157, 180, 246, 131, 220, 82, 104, 72, 73,
        75, 43, 69, 139, 216, 167, 145, 220, 67, 168, 144, 173, 88, 35, 127, 234, 194, 83, 189,
        172, 65, 29, 156, 73, 98, 87, 231, 87, 129, 15, 235, 127, 125, 97, 211, 51, 212, 211, 2,
        13, 36, 123, 53, 12, 31, 191, 40, 13, 175,
    ];

    fn algorithms() -> [CoseContentEncryptionAlgorithm; 3] {
        [
            CoseContentEncryptionAlgorithm::Aes256Gcm,
            CoseContentEncryptionAlgorithm::XAes256Gcm,
            CoseContentEncryptionAlgorithm::XChaCha20Poly1305,
        ]
    }

    fn make_xaes_key() -> XAes256GcmKey {
        XAes256GcmKey {
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
            let decrypted =
                decrypt_cose(&cose_encrypt, CoseAlgorithmPolicy::Exactly(algorithm), &CEK).unwrap();
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
            let decrypted = decrypt_cose0(
                &cose_encrypt0,
                CoseAlgorithmPolicy::Exactly(algorithm),
                &CEK,
            )
            .unwrap();
            assert_eq!(decrypted, PLAINTEXT);
        }
    }

    #[test]
    fn test_decrypt_cose_algorithm_policies() {
        let builder =
            || CoseEncryptBuilder::new().add_recipient(CoseRecipientBuilder::new().build());
        let message = encrypt_cose(
            CoseContentEncryptionAlgorithm::XChaCha20Poly1305,
            builder(),
            HeaderBuilder::new().build(),
            PLAINTEXT,
            &CEK,
        )
        .unwrap();

        assert_eq!(
            decrypt_cose(
                &message,
                CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::XChaCha20Poly1305,),
                &CEK,
            )
            .unwrap(),
            PLAINTEXT
        );
        assert!(matches!(
            decrypt_cose(
                &message,
                CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::Aes256Gcm),
                &CEK,
            ),
            Err(CryptoError::WrongKeyType)
        ));
        assert_eq!(
            decrypt_cose(
                &message,
                CoseAlgorithmPolicy::ProtectedHeaderAlgorithmOrLegacyDefault(
                    CoseContentEncryptionAlgorithm::Aes256Gcm,
                ),
                &CEK,
            )
            .unwrap(),
            PLAINTEXT
        );

        let missing_algorithm = builder()
            .protected(HeaderBuilder::new().build())
            .create_ciphertext(PLAINTEXT, &[], |data, _| data.to_vec())
            .build();
        for policy in [
            CoseAlgorithmPolicy::RequireProtectedHeaderAlgorithm,
            CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::XChaCha20Poly1305),
        ] {
            assert!(matches!(
                decrypt_cose(&missing_algorithm, policy, &CEK),
                Err(CryptoError::EncString(
                    EncStringParseError::CoseMissingAlgorithm
                ))
            ));
        }

        let nonce = XChaCha20Poly1305Nonce::make();
        let legacy_message = builder()
            .protected(HeaderBuilder::new().build())
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(PLAINTEXT, &[], |data, aad| {
                XChaCha20Poly1305::encrypt(&CEK, &nonce, data, aad)
                    .encrypted_bytes()
                    .to_vec()
            })
            .build();
        assert_eq!(
            decrypt_cose(
                &legacy_message,
                CoseAlgorithmPolicy::ProtectedHeaderAlgorithmOrLegacyDefault(
                    CoseContentEncryptionAlgorithm::XChaCha20Poly1305,
                ),
                &CEK,
            )
            .unwrap(),
            PLAINTEXT
        );
    }

    #[test]
    fn test_decrypt_cose0_algorithm_policies() {
        let message = encrypt_cose0(
            CoseContentEncryptionAlgorithm::XChaCha20Poly1305,
            CoseEncrypt0Builder::new(),
            HeaderBuilder::new().build(),
            PLAINTEXT,
            &CEK,
        )
        .unwrap();

        assert_eq!(
            decrypt_cose0(
                &message,
                CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::XChaCha20Poly1305,),
                &CEK,
            )
            .unwrap(),
            PLAINTEXT
        );
        assert!(matches!(
            decrypt_cose0(
                &message,
                CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::Aes256Gcm),
                &CEK,
            ),
            Err(CryptoError::WrongKeyType)
        ));
        assert_eq!(
            decrypt_cose0(
                &message,
                CoseAlgorithmPolicy::ProtectedHeaderAlgorithmOrLegacyDefault(
                    CoseContentEncryptionAlgorithm::Aes256Gcm,
                ),
                &CEK,
            )
            .unwrap(),
            PLAINTEXT
        );

        let missing_algorithm = CoseEncrypt0Builder::new()
            .protected(HeaderBuilder::new().build())
            .create_ciphertext(PLAINTEXT, &[], |data, _| data.to_vec())
            .build();
        assert!(matches!(
            decrypt_cose0(
                &missing_algorithm,
                CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::XChaCha20Poly1305),
                &CEK,
            ),
            Err(CryptoError::EncString(
                EncStringParseError::CoseMissingAlgorithm
            ))
        ));
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
        assert!(
            decrypt_cose0(
                &cose_encrypt0,
                CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::XChaCha20Poly1305),
                &wrong_cek
            )
            .is_err()
        );
    }

    #[test]
    fn test_decrypt_xaes256_gcm_wrong_key_fails() {
        let cose_encrypt0 = encrypt_cose0(
            CoseContentEncryptionAlgorithm::XAes256Gcm,
            CoseEncrypt0Builder::new(),
            HeaderBuilder::new().build(),
            PLAINTEXT,
            &CEK,
        )
        .unwrap();

        assert!(matches!(
            decrypt_cose0(
                &cose_encrypt0,
                CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::XAes256Gcm),
                &[0u8; 32]
            ),
            Err(CryptoError::KeyDecrypt)
        ));
    }

    #[test]
    fn test_xaes256_gcm_emits_24_byte_nonce() {
        let cose_encrypt = encrypt_cose(
            CoseContentEncryptionAlgorithm::XAes256Gcm,
            CoseEncryptBuilder::new().add_recipient(CoseRecipientBuilder::new().build()),
            HeaderBuilder::new().build(),
            PLAINTEXT,
            &CEK,
        )
        .unwrap();
        let cose_encrypt0 = encrypt_cose0(
            CoseContentEncryptionAlgorithm::XAes256Gcm,
            CoseEncrypt0Builder::new(),
            HeaderBuilder::new().build(),
            PLAINTEXT,
            &CEK,
        )
        .unwrap();

        assert_eq!(cose_encrypt.unprotected.iv.len(), 24);
        assert_eq!(cose_encrypt0.unprotected.iv.len(), 24);
    }

    #[test]
    fn test_decrypt_xaes256_gcm_wrong_nonce_fails() {
        let mut cose_encrypt0 = encrypt_cose0(
            CoseContentEncryptionAlgorithm::XAes256Gcm,
            CoseEncrypt0Builder::new(),
            HeaderBuilder::new().build(),
            PLAINTEXT,
            &CEK,
        )
        .unwrap();
        cose_encrypt0.unprotected.iv[0] ^= 1;

        assert!(matches!(
            decrypt_cose0(
                &cose_encrypt0,
                CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::XAes256Gcm),
                &CEK
            ),
            Err(CryptoError::KeyDecrypt)
        ));
    }

    #[test]
    fn test_decrypt_xaes256_gcm_malformed_nonce_fails() {
        let mut cose_encrypt0 = encrypt_cose0(
            CoseContentEncryptionAlgorithm::XAes256Gcm,
            CoseEncrypt0Builder::new(),
            HeaderBuilder::new().build(),
            PLAINTEXT,
            &CEK,
        )
        .unwrap();
        cose_encrypt0.unprotected.iv.pop();

        assert!(matches!(
            decrypt_cose0(
                &cose_encrypt0,
                CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::XAes256Gcm),
                &CEK
            ),
            Err(CryptoError::InvalidNonceLength)
        ));
    }

    #[test]
    fn test_decrypt_cose0_missing_algorithm_fails_without_default() {
        // A message with no declared algorithm and no fallback cannot be dispatched.
        let cose_encrypt0 = CoseEncrypt0Builder::new()
            .protected(HeaderBuilder::new().build())
            .create_ciphertext(PLAINTEXT, &[], |data, _| data.to_vec())
            .build();
        assert!(matches!(
            decrypt_cose0(
                &cose_encrypt0,
                CoseAlgorithmPolicy::RequireProtectedHeaderAlgorithm,
                &CEK
            ),
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
            CoseAlgorithmPolicy::ProtectedHeaderAlgorithmOrLegacyDefault(
                CoseContentEncryptionAlgorithm::XChaCha20Poly1305,
            ),
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
        let encrypted = encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::CoseKey).unwrap();
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
        let serialized_message = CoseEncrypt0Bytes::from(cose_encrypt0.to_vec().unwrap());

        let key = make_xchacha_key();
        assert!(matches!(
            decrypt_xchacha20_poly1305(&serialized_message, &key),
            Err(CryptoError::WrongKeyType)
        ));
    }

    fn xaes_message(content_format: ContentFormat) -> CoseEncrypt0 {
        let encoded =
            encrypt_xaes256_gcm(TEST_VECTOR_PLAINTEXT, &make_xaes_key(), content_format).unwrap();
        CoseEncrypt0::from_slice(encoded.as_ref()).unwrap()
    }

    fn rebuild_xaes_message(message: CoseEncrypt0, protected: Header) -> CoseEncrypt0Bytes {
        CoseEncrypt0Builder::new()
            .protected(protected)
            .unprotected(message.unprotected)
            .ciphertext(message.ciphertext.unwrap())
            .build()
            .to_vec()
            .unwrap()
            .into()
    }

    #[test]
    fn test_xaes256_gcm_roundtrip_content_formats() {
        for content_format in [
            ContentFormat::OctetStream,
            ContentFormat::Utf8,
            ContentFormat::Pkcs8PrivateKey,
            ContentFormat::CoseKey,
        ] {
            let encrypted =
                encrypt_xaes256_gcm(TEST_VECTOR_PLAINTEXT, &make_xaes_key(), content_format)
                    .unwrap();
            assert_eq!(
                decrypt_xaes256_gcm(&encrypted, &make_xaes_key()).unwrap(),
                (TEST_VECTOR_PLAINTEXT.to_vec(), content_format)
            );
        }
    }

    #[test]
    fn test_xaes256_gcm_key_id_and_authentication_failures() {
        let encrypted = encrypt_xaes256_gcm(
            TEST_VECTOR_PLAINTEXT,
            &make_xaes_key(),
            ContentFormat::OctetStream,
        )
        .unwrap();

        let mut wrong_bytes = make_xaes_key();
        wrong_bytes.enc_key[0] ^= 1;
        assert!(matches!(
            decrypt_xaes256_gcm(&encrypted, &wrong_bytes),
            Err(CryptoError::KeyDecrypt)
        ));

        let mut wrong_id = make_xaes_key();
        wrong_id.key_id = KeyId::from([1; 16]);
        assert!(matches!(
            decrypt_xaes256_gcm(&encrypted, &wrong_id),
            Err(CryptoError::WrongCoseKeyId)
        ));
    }

    #[test]
    fn test_xaes256_gcm_rejects_invalid_protected_headers() {
        let key = make_xaes_key();

        let mut message = xaes_message(ContentFormat::OctetStream);
        message.protected.header.alg = Some(Algorithm::Assigned(iana::Algorithm::A256GCM));
        let encrypted = rebuild_xaes_message(message.clone(), message.protected.header.clone());
        assert!(matches!(
            decrypt_xaes256_gcm(&encrypted, &key),
            Err(CryptoError::WrongKeyType)
        ));

        message.protected.header.alg = None;
        let encrypted = rebuild_xaes_message(message.clone(), message.protected.header.clone());
        assert!(matches!(
            decrypt_xaes256_gcm(&encrypted, &key),
            Err(CryptoError::EncString(
                EncStringParseError::CoseMissingAlgorithm
            ))
        ));

        for content_type in [
            None,
            Some(coset::ContentType::Text("application/unsupported".into())),
        ] {
            message.protected.header.alg = Some(Algorithm::PrivateUse(XAES_256_GCM));
            message.protected.header.content_type = content_type;
            let encrypted = rebuild_xaes_message(message.clone(), message.protected.header.clone());
            assert!(matches!(
                decrypt_xaes256_gcm(&encrypted, &key),
                Err(CryptoError::EncString(
                    EncStringParseError::CoseMissingContentType
                ))
            ));
        }
    }

    #[test]
    fn test_xaes256_gcm_rejects_missing_or_malformed_fields() {
        let key = make_xaes_key();
        let mut message = xaes_message(ContentFormat::OctetStream);
        message.ciphertext = None;
        let encrypted = message.to_vec().unwrap().into();
        assert!(matches!(
            decrypt_xaes256_gcm(&encrypted, &key),
            Err(CryptoError::MissingField("ciphertext"))
        ));

        let mut message = xaes_message(ContentFormat::OctetStream);
        message.unprotected.iv.pop();
        let encrypted = message.to_vec().unwrap().into();
        assert!(matches!(
            decrypt_xaes256_gcm(&encrypted, &key),
            Err(CryptoError::InvalidNonceLength)
        ));

        assert!(matches!(
            decrypt_xaes256_gcm(&CoseEncrypt0Bytes::from([0xff].as_slice()), &key),
            Err(CryptoError::EncString(
                EncStringParseError::InvalidCoseEncoding(_)
            ))
        ));
    }

    #[test]
    fn test_xaes256_gcm_rejects_invalid_padding() {
        let key = make_xaes_key();
        let nonce = XAes256GcmNonce::make();
        let mut protected = HeaderBuilder::from(ContentFormat::Utf8)
            .key_id(KEY_ID.to_vec())
            .build();
        protected.alg = Some(Algorithm::PrivateUse(XAES_256_GCM));
        let message = CoseEncrypt0Builder::new()
            .protected(protected)
            .unprotected(HeaderBuilder::new().iv(nonce.as_bytes().to_vec()).build())
            .create_ciphertext(&[0], &[], |data, aad| {
                XAes256Gcm::encrypt(&KEY_DATA, &nonce, data, aad)
                    .encrypted_bytes()
                    .to_vec()
            })
            .build()
            .to_vec()
            .unwrap()
            .into();

        assert!(matches!(
            decrypt_xaes256_gcm(&message, &key),
            Err(CryptoError::InvalidPadding)
        ));
    }
}
