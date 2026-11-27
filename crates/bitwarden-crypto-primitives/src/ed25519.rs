//! Ed25519 signatures (RFC 8032).

use zeroize::Zeroizing;

use crate::{Error, backend};

/// Seed (private key) length in bytes.
pub const SEED_LEN: usize = 32;
/// Public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Ed25519 signing key. Zeroized on drop.
#[derive(Clone)]
pub struct SigningKey(backend::ed25519::SigningKey);

impl zeroize::ZeroizeOnDrop for SigningKey where backend::ed25519::SigningKey: zeroize::ZeroizeOnDrop
{}

impl SigningKey {
    /// Generates a fresh key.
    pub fn generate() -> Self {
        Self(backend::ed25519::SigningKey::generate())
    }

    /// Builds a key from its 32-byte seed.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self(backend::ed25519::SigningKey::from_seed(seed))
    }

    /// Returns the 32-byte seed.
    pub fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        self.0.seed()
    }

    /// Returns the matching verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Signs `msg` (pure Ed25519, deterministic).
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(msg)
    }
}

/// Ed25519 verifying key.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey(backend::ed25519::VerifyingKey);

impl VerifyingKey {
    /// Parses a compressed point.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, Error> {
        backend::ed25519::VerifyingKey::from_bytes(bytes).map(Self)
    }

    /// Returns the compressed point.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verifies `sig` over `msg`. Rejects small-order keys and non-canonical signatures.
    pub fn verify(&self, msg: &[u8], sig: &[u8; SIGNATURE_LEN]) -> Result<(), Error> {
        self.0.verify(msg, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::array;

    // RFC 8032 §7.1 test 1.
    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    #[test]
    fn known_answer() {
        let key = SigningKey::from_seed(&array(SEED));
        assert_eq!(hex::encode(key.verifying_key().to_bytes()), PUBLIC);
        assert_eq!(hex::encode(key.sign(b"")), SIG);
        assert_eq!(*key.seed(), array::<SEED_LEN>(SEED));

        let vk = VerifyingKey::from_bytes(&array(PUBLIC)).expect("valid point");
        assert_eq!(vk.verify(b"", &array(SIG)), Ok(()));
    }

    #[test]
    fn rejects_wrong_message_and_key() {
        let key = SigningKey::generate();
        let sig = key.sign(b"msg");
        assert_eq!(key.verifying_key().verify(b"msg", &sig), Ok(()));
        assert_eq!(
            key.verifying_key().verify(b"other", &sig),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            SigningKey::generate().verifying_key().verify(b"msg", &sig),
            Err(Error::InvalidSignature)
        );
    }

    /// Deterministic signatures under a fixed seed, including over the empty message.
    #[test]
    fn known_answers_fixed_seed() {
        const SEED_42: &str = "4242424242424242424242424242424242424242424242424242424242424242";
        const FOX: &str = "The quick brown fox jumps over the lazy dog";

        let key = SigningKey::from_seed(&array(SEED_42));
        let public = key.verifying_key();
        assert_eq!(
            hex::encode(public.to_bytes()),
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
        );

        let cases = [
            (
                "",
                "3f9f3147d0dd159f334cb800435ae49a2837adae5e6b2394906edc2cfed82978\
                5e3dd186eb2fed1319a0451917cb6617fcbe9382e0d1343eb5ffd4a9a2dd820c",
            ),
            (
                FOX,
                "e868bd83b3daa5114b47f99e42c795f4c65018cbc150341e351f1eb54f5707a8\
                0bec06c54ded44beb9f1e9321f04e72af1844839f23eafce8c9a0beb7b86410a",
            ),
        ];
        for (msg, expected) in cases {
            let msg = msg.as_bytes();
            let sig = key.sign(msg);
            assert_eq!(hex::encode(sig), expected);
            assert_eq!(public.verify(msg, &sig), Ok(()));
        }
    }
}
