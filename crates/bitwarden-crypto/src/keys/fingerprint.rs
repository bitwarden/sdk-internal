//! This module provides functionality to generate a cryptographic fingerprint for a public key.
//! This is based on a set of parts of a public key, for RSA this can be the modulus and exponent,
//! in canonical form.
//!
//! Currently, only SHA256 is supported, but the format is designed to be extensible, to more
//! algorithms in the future, should SHA256 ever not fulfill the required security properties.
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Security assumption:
/// - The hash function has second pre-image resistance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum PublicKeyFingerprintAlgorithm {
    Sha256 = 1,
}

/// A fingerprint represents a short, canonical representation of a public key.
/// When signing a key, or showing a key to a user, this representation is used.
///
/// Note: This implies that a key can have multiple fingerprints. Under a given algorithm,
/// the fingerprint is always the same, but under different algorithms, the fingerprint is also
/// different.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PublicKeyFingerprint {
    pub(crate) digest: serde_bytes::ByteBuf,
    pub(crate) algorithm: PublicKeyFingerprintAlgorithm,
}

/// A trait for objects that can have a canonical cryptographic fingerprint derived from them. To
/// implement this trait, the object should implement the `FingerprintableKey` trait.
pub(crate) trait Fingerprintable {
    /// Returns a fingerprint for the public key, using the currently recommended algorithm.
    fn fingerprint(&self) -> PublicKeyFingerprint;
    /// Verify that a fingerprint is valid for the public key
    fn verify_fingerprint(&self, fingerprint: &PublicKeyFingerprint) -> bool;
}

pub(crate) trait FingerprintableKey: Fingerprintable {
    /// Returns a canonical representation of the public key.
    /// The entries of the returned vector should not contain data that is a non-injective mapping
    /// of the public key. For instance, for RSA, the modulus and exponent should be returned
    /// separately, not concatenated.
    fn fingerprint_parts(&self) -> Vec<Vec<u8>>;
}

impl<T: FingerprintableKey> Fingerprintable for T {
    fn fingerprint(&self) -> PublicKeyFingerprint {
        let fingerprint_parts = self.fingerprint_parts();
        derive_fingerprint(fingerprint_parts)
    }

    fn verify_fingerprint(&self, fingerprint: &PublicKeyFingerprint) -> bool {
        let fingerprint_parts = self.fingerprint_parts();
        verify_fingerprint(fingerprint, fingerprint_parts)
    }
}

/// Derives a fingerprint using a currently supported algorithm.
/// Fingerprint_parts must be a canonical set of parts representing the public key.
///
/// The encoding needs to be canonical. That is, something like DER or PEM does *not* work,
/// because the encoding could differ slightly between implementations. For RSA, using the modulus
/// and exponent directly works.
fn derive_fingerprint(fingerprint_parts: Vec<Vec<u8>>) -> PublicKeyFingerprint {
    derive_fingerprint_from_parts(fingerprint_parts)
}

/// This function ensures an injective mapping of the inputs to the output hash.
/// Concatenating the inputs does not work. For RSA this could mean that:
/// with data = [N,E], |nnnnnn|ee|, and |nnnnnnn|e| would both be valid interpretations of the
/// concatenation of the bytes, and thus may lead to the same hash for different (N,E) pairs.
///
/// This function hashes each input separately, concatenates the hashes, and then hashes the result.
/// Assumption: H is a cryptographic hash function, with respect to:
/// - Second pre-image resistance
/// Assumption: H's output has a constant length output HS
///
/// Specifically, the construction is:
/// H(H(data1)|H(data2)|...|H(dataN))
///
/// Given the assumptions above, then hashing each input separately, and concatenating the hashes is
/// an injective mapping. Because there is an injective mapping, and because of collision resistance
/// w.r.t. the final hash functions inputs, this also implies collision resistance w.r.t. data.
fn derive_fingerprint_from_parts(data: Vec<Vec<u8>>) -> PublicKeyFingerprint {
    let hash_set = data
        .iter()
        .map(|d| derive_fingerprint_single(d))
        .collect::<Vec<_>>();
    let concat = hash_set
        .iter()
        .flat_map(|h| h.digest.clone())
        .collect::<Vec<_>>();
    derive_fingerprint_single(&concat)
}

fn derive_fingerprint_single(data: &[u8]) -> PublicKeyFingerprint {
    PublicKeyFingerprint {
        digest: sha2::Sha256::digest(data).to_vec().into(),
        algorithm: PublicKeyFingerprintAlgorithm::Sha256,
    }
}

/// Verifies a fingerprint for a given public key, represented as a canonical list of parts.
fn verify_fingerprint(fingerprint: &PublicKeyFingerprint, fingerprint_parts: Vec<Vec<u8>>) -> bool {
    match fingerprint.algorithm {
        PublicKeyFingerprintAlgorithm::Sha256 => {
            let hash = derive_fingerprint_from_parts(fingerprint_parts);
            hash.digest == fingerprint.digest
        }
    }
}
