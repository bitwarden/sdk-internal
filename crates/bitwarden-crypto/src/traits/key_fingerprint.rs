/// Fingerprints are 256-bit. Anything human readable can be derived from that. This is enough entropy for
/// all uses cases.
const FINGERPRINT_LENGTH: usize = 32;

/// A key fingerprint is a short, unique identifier for a cryptographic key. It is typically derived
/// from the key material using a cryptographic hash function. It also has a pseudo-random distribution and
/// MUST be derived using a cryptographic hash function / there MUST NOT be direct control over the output.
pub struct KeyFingerprint(pub(crate) [u8; FINGERPRINT_LENGTH]);

/// A trait for deriving a key fingerprint from a cryptographic key. To implement, this MUST take a canonical representation
/// of a public key of a signing, or public-key-encryption key pair, and derive the fingerprint material from that.
/// 
/// This canonical representation MUST be stable, and MUST not collide with other representations. For key pairs that have multiple
/// components, such as RSA, a valid implementation MUST explain why the chosen representation is canonical and non-colliding.
/// 
/// It is recommended to use a reasonable cryptographic hashing function, such as SHA-256 to derive the 256-Bit fingerprint from the canonical representation that can have arbitrary length.
/// Once implemented, for a key algorithm type the fingerprint MUST not change, because other cryptographic objects will rely on it, and plugging different fingerprint algorithms for a given public-key
/// algorithm is not supported. A new public key algorithm may choose a new implementation, with different canonical representation and/or hash function.
pub trait DeriveFingerprint {
    fn fingerprint(&self) -> KeyFingerprint;
}