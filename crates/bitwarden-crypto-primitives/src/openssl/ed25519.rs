use ::openssl::{
    pkey::{Id, PKey, Private, Public},
    sign::{Signer, Verifier},
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use zeroize::Zeroizing;

use crate::Error;

/// Seed / public key length in bytes.
const KEY_LEN: usize = 32;
/// Signature length in bytes.
const SIGNATURE_LEN: usize = 64;

#[derive(Clone)]
pub(crate) struct SigningKey(PKey<Private>);

// OpenSSL frees the raw private key with `OPENSSL_clear_free`.
impl zeroize::ZeroizeOnDrop for SigningKey {}

impl SigningKey {
    pub(crate) fn generate() -> Self {
        Self(PKey::generate_ed25519().expect("Ed25519 key generation does not fail"))
    }

    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        Self(
            PKey::private_key_from_raw_bytes(seed, Id::ED25519)
                .expect("every 32-byte string is an Ed25519 seed"),
        )
    }

    pub(crate) fn seed(&self) -> Zeroizing<[u8; 32]> {
        let raw = Zeroizing::new(
            self.0
                .raw_private_key()
                .expect("Ed25519 keys export their raw seed"),
        );
        Zeroizing::new(raw.as_slice().try_into().expect("Ed25519 seed is 32 bytes"))
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        let raw = self
            .0
            .raw_public_key()
            .expect("Ed25519 keys export their raw public key");
        let bytes = raw
            .as_slice()
            .try_into()
            .expect("Ed25519 public key is 32 bytes");
        VerifyingKey::from_bytes(&bytes).expect("a derived public key is a valid point")
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        const INFALLIBLE: &str = "Ed25519 signing of in-memory data does not fail";

        let mut signer = Signer::new_without_digest(&self.0).expect(INFALLIBLE);
        let mut sig = [0u8; SIGNATURE_LEN];
        signer.sign_oneshot(&mut sig, msg).expect(INFALLIBLE);
        sig
    }
}

/// Raw encoding plus the OpenSSL key. Equality compares the encoding.
#[derive(Clone)]
pub(crate) struct VerifyingKey {
    bytes: [u8; KEY_LEN],
    key: PKey<Public>,
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for VerifyingKey {}

impl VerifyingKey {
    /// OpenSSL stores any 32 bytes as a key; decompress here to reject non-points like the
    /// RustCrypto backend does.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        if CompressedEdwardsY(*bytes).decompress().is_none() {
            return Err(Error::InvalidKey);
        }

        let key =
            PKey::public_key_from_raw_bytes(bytes, Id::ED25519).map_err(|_| Error::InvalidKey)?;
        Ok(Self { bytes: *bytes, key })
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Strict verification: rejects small-order keys and non-canonical signatures.
    ///
    /// OpenSSL verifies cofactorless, rejects `s >= L`, and compares `R` byte-for-byte with the
    /// recomputed point. It does not reject small-order `A` or `R`, so both are checked here first
    /// to match `ed25519_dalek::VerifyingKey::verify_strict`. Remaining gap: a non-canonical
    /// encoding of `R` fails here, while dalek compares decoded points and could accept it. Honest
    /// signers never produce one.
    pub(crate) fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
        let r: [u8; KEY_LEN] = sig[..KEY_LEN].try_into().expect("R is the first 32 bytes");
        if is_weak(&self.bytes) || is_weak(&r) {
            return Err(Error::InvalidSignature);
        }

        let mut verifier =
            Verifier::new_without_digest(&self.key).map_err(|_| Error::InvalidSignature)?;
        match verifier.verify_oneshot(sig, msg) {
            Ok(true) => Ok(()),
            _ => Err(Error::InvalidSignature),
        }
    }
}

/// Whether `bytes` fails to decode or decodes to a small-order point.
fn is_weak(bytes: &[u8; KEY_LEN]) -> bool {
    CompressedEdwardsY(*bytes)
        .decompress()
        .is_none_or(|point| point.is_small_order())
}
