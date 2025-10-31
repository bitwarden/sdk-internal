//! Implements Parabel-Jose-PQ-composite-sigs
//! https://www.ietf.org/archive/id/draft-prabel-jose-pq-composite-sigs-04.html

use ml_dsa::{B32, EncodedVerifyingKey, KeyGen, MlDsa65};
use rand::RngCore;
use sha2::Digest;

const ML_DSA_SEED_SIZE: usize = 32;
const RANDOMIZER_SIZE: usize = 32;

const COMPOSITE_ALGORITHM_SIGNATURE_PREFIX: &[u8] = &[
    0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x65, 0x41, 0x6C, 0x67, 0x6F, 0x72, 0x69, 0x74,
    0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35,
];

const ML_DSA65_ED25519_DOMAIN_SEPARATOR: &[u8] = &[
    0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x09, 0x01, 0x0B,
];

struct Mldsa65Ed25519SigningKey {
    mldsa65_seed: [u8; ML_DSA_SEED_SIZE],
    ed25519_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
}

impl Into<Vec<u8>> for Mldsa65Ed25519SigningKey {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::with_capacity(ML_DSA_SEED_SIZE + ed25519_dalek::SECRET_KEY_LENGTH);
        v.extend_from_slice(&self.mldsa65_seed);
        v.extend_from_slice(&self.ed25519_key);
        v
    }
}

impl From<Vec<u8>> for Mldsa65Ed25519SigningKey {
    fn from(bytes: Vec<u8>) -> Self {
        let mut mldsa65_seed = [0u8; ML_DSA_SEED_SIZE];
        mldsa65_seed.copy_from_slice(&bytes[0..ML_DSA_SEED_SIZE]);
        let mut ed25519_key = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        ed25519_key.copy_from_slice(&bytes[ML_DSA_SEED_SIZE..]);
        Mldsa65Ed25519SigningKey {
            mldsa65_seed,
            ed25519_key,
        }
    }
}

struct MlDsa65Ed25519VerifyingKey {
    mldsa65_key: ml_dsa::VerifyingKey<MlDsa65>,
    ed25519_key: ed25519_dalek::VerifyingKey,
}

impl Into<Vec<u8>> for MlDsa65Ed25519VerifyingKey {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.mldsa65_key.encode().as_slice());
        v.extend_from_slice(self.ed25519_key.to_bytes().as_slice());
        v
    }
}

struct MlDsa65Ed25519Signature {
    r: [u8; RANDOMIZER_SIZE],
    mldsa65_signature: ml_dsa::Signature<MlDsa65>,
    ed25519_signature: ed25519_dalek::Signature,
}

impl Mldsa65Ed25519SigningKey {
    fn make() -> Self {
        let mut mldsa65_seed = [0u8; ML_DSA_SEED_SIZE];
        rand::rng().fill_bytes(&mut mldsa65_seed);
        let ed25519_key = ed25519_dalek::SigningKey::generate(&mut rand::rng()).to_bytes();
        Mldsa65Ed25519SigningKey {
            mldsa65_seed,
            ed25519_key,
        }
    }

    fn to_verifying_key(&self) -> MlDsa65Ed25519VerifyingKey {
        let mldsa65_key = MlDsa65::key_gen_internal(&B32::from(self.mldsa65_seed))
            .verifying_key()
            .to_owned();
        let ed25519_key = ed25519_dalek::SigningKey::from_bytes(&self.ed25519_key).verifying_key();
        MlDsa65Ed25519VerifyingKey {
            mldsa65_key,
            ed25519_key,
        }
    }

    fn sign(&self, message: &[u8]) -> MlDsa65Ed25519Signature {
        let mut r = [0u8; RANDOMIZER_SIZE];
        rand::rng().fill_bytes(&mut r);
        let m = mldsa65_ed25519_compute_m(message, r);

        let mldsa65_signature = {
            use ml_dsa::signature::Signer;
            MlDsa65::key_gen_internal(&B32::from(self.mldsa65_seed))
                .signing_key()
                // todo this is wrong, and should have the CTX set to domain
                .try_sign(m.as_slice())
                .expect("Signing always succeeds with valid key")
        };
        let ed25519_signature = {
            use ed25519_dalek::Signer;
            ed25519_dalek::SigningKey::from_bytes(&self.ed25519_key).sign(message)
        };

        MlDsa65Ed25519Signature {
            r,
            mldsa65_signature,
            ed25519_signature,
        }
    }
}

impl MlDsa65Ed25519VerifyingKey {
    fn verify(&self, message: &[u8], signature: &MlDsa65Ed25519Signature) -> bool {
        let m = mldsa65_ed25519_compute_m(message, signature.r);
        let mldsa65_valid = {
            use ml_dsa::signature::Verifier;
            println!("Verifying MlDsa65Ed25519 signature...");
            self.mldsa65_key
                .verify(m.as_slice(), &signature.mldsa65_signature)
                .is_ok()
        };
        let ed25519_valid = {
            println!("Verifying Ed25519 part of MlDsa65Ed25519 signature...");
            self.ed25519_key
                .verify_strict(message, &signature.ed25519_signature)
                .is_ok()
        };
        mldsa65_valid && ed25519_valid
    }
}

fn mldsa65_ed25519_compute_m(message: &[u8], r: [u8; RANDOMIZER_SIZE]) -> Vec<u8> {
    // Sha512 is specific to MlDsa65Ed25519
    let pre_hash = sha2::Sha512::digest(message);
    let m = [
        COMPOSITE_ALGORITHM_SIGNATURE_PREFIX,
        ML_DSA65_ED25519_DOMAIN_SEPARATOR,
        &[0x00],
        pre_hash.as_slice(),
    ]
    .concat();
    m
}

mod tests {
    use super::*;

    #[test]
    fn test_mldsa65_ed25519_signature() {
        let signing_key = Mldsa65Ed25519SigningKey::make();
        let verifying_key = signing_key.to_verifying_key();
        let message = b"Test message for MlDsa65Ed25519 composite signature";
        let signature = signing_key.sign(message);
        assert!(verifying_key.verify(message, &signature));
    }
}
