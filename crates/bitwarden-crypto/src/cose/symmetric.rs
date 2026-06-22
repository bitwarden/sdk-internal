//! Content encryption of COSE `CoseEncrypt`/`CoseEncrypt0` messages by the hazmat symmetric
//! ciphers.
//!
//! The [`CoseEncryptCipher`] trait adds `encrypt_cose`/`decrypt_cose` (multi-recipient
//! [`CoseEncrypt`]) and `encrypt_cose0`/`decrypt_cose0` (single-recipient [`CoseEncrypt0`]) to an
//! [`Aead`] cipher: the caller supplies the content-encryption key (CEK) - typically derived via a
//! KDF or held in the key store - and the protected headers, while the cipher owns the
//! symmetric-encryption details. The cipher declares its COSE content-encryption algorithm in the
//! protected header (so it is authenticated as associated data) and a fresh nonce is generated per
//! message and stored in the unprotected `iv` header.
//!
//! Two ciphers are implemented, and the message shape (single- vs multi-recipient) is orthogonal to
//! the cipher choice:
//! - AES-256-GCM, used by the
//!   [`SecretProtectedKeyEnvelope`](crate::safe::SecretProtectedKeyEnvelope) over [`CoseEncrypt`].
//!   AES-GCM is sound here because the CEK is locally derived and unique per message, so there is
//!   no nonce-reuse problem. See [`crate::hazmat::symmetric_encryption::aes_gcm`] for the caveats.
//! - XChaCha20-Poly1305, used by the [`SymmetricKeyEnvelope`](crate::safe::SymmetricKeyEnvelope)
//!   over [`CoseEncrypt0`]. It uses a private-use COSE algorithm identifier (see
//!   [`XCHACHA20_POLY1305`]).

use coset::{
    Algorithm, CoseEncrypt, CoseEncrypt0, CoseEncrypt0Builder, CoseEncryptBuilder, Header,
    HeaderBuilder, iana,
};

use super::XCHACHA20_POLY1305;
use crate::{
    CryptoError,
    error::EncStringParseError,
    hazmat::symmetric_encryption::{
        Aead,
        aes_gcm::{Aes256Gcm, Aes256GcmCiphertext, Aes256GcmNonce},
        xchacha20::{XChaCha20Poly1305, XChaCha20Poly1305Ciphertext, XChaCha20Poly1305Nonce},
    },
};

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
/// Some legacy envelopes (notably early [`PasswordProtectedKeyEnvelope`](crate::safe::PasswordProtectedKeyEnvelope)s)
/// were sealed without declaring the content-encryption algorithm in their protected header. Callers
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
pub(crate) fn encrypt_cose(
    algorithm: CoseContentEncryptionAlgorithm,
    builder: CoseEncryptBuilder,
    protected_header: Header,
    plaintext: &[u8],
    cek: &[u8],
) -> Result<CoseEncrypt, CryptoError> {
    match algorithm {
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let cek: &<Aes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(Aes256Gcm::encrypt_cose(
                builder,
                protected_header,
                plaintext,
                cek,
            ))
        }
        CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
            let cek: &<XChaCha20Poly1305 as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(XChaCha20Poly1305::encrypt_cose(
                builder,
                protected_header,
                plaintext,
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
    match algorithm_from_header(&cose_encrypt.protected.header, default_algorithm)? {
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let cek: &<Aes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Aes256Gcm::decrypt_cose(cose_encrypt, cek)
        }
        CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
            let cek: &<XChaCha20Poly1305 as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            XChaCha20Poly1305::decrypt_cose(cose_encrypt, cek)
        }
    }
}

/// Encrypts `plaintext` into a single-recipient COSE [`CoseEncrypt0`] message, dispatching to the
/// [`CoseEncryptCipher`] selected by `algorithm`.
///
/// As with [`encrypt_cose`], the cipher declares its algorithm in the (authenticated) protected
/// header so [`decrypt_cose0`] can recover it. `cek` is the content-encryption key and must match
/// the selected cipher's key length.
pub(crate) fn encrypt_cose0(
    algorithm: CoseContentEncryptionAlgorithm,
    builder: CoseEncrypt0Builder,
    protected_header: Header,
    plaintext: &[u8],
    cek: &[u8],
) -> Result<CoseEncrypt0, CryptoError> {
    match algorithm {
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let cek: &<Aes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(Aes256Gcm::encrypt_cose0(
                builder,
                protected_header,
                plaintext,
                cek,
            ))
        }
        CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
            let cek: &<XChaCha20Poly1305 as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Ok(XChaCha20Poly1305::encrypt_cose0(
                builder,
                protected_header,
                plaintext,
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
    match algorithm_from_header(&cose_encrypt0.protected.header, default_algorithm)? {
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let cek: &<Aes256Gcm as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            Aes256Gcm::decrypt_cose0(cose_encrypt0, cek)
        }
        CoseContentEncryptionAlgorithm::XChaCha20Poly1305 => {
            let cek: &<XChaCha20Poly1305 as Aead>::Key =
                cek.try_into().map_err(|_| CryptoError::InvalidKeyLen)?;
            XChaCha20Poly1305::decrypt_cose0(cose_encrypt0, cek)
        }
    }
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

#[cfg(test)]
mod tests {
    use coset::{CoseEncrypt0Builder, CoseEncryptBuilder, CoseRecipientBuilder, HeaderBuilder};

    use super::*;

    const CEK: [u8; 32] = [7u8; 32];
    const PLAINTEXT: &[u8] = b"content-encryption test vector";

    fn algorithms() -> [CoseContentEncryptionAlgorithm; 2] {
        [
            CoseContentEncryptionAlgorithm::Aes256Gcm,
            CoseContentEncryptionAlgorithm::XChaCha20Poly1305,
        ]
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
}
