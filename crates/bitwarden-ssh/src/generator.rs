use rand::CryptoRng;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, EcdsaCurve};

use crate::{
    SshKeyData,
    error::{self, KeyGenerationError},
    ssh_private_key_to_data,
};

#[derive(Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyAlgorithm {
    Ed25519,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    /// `ssh-mldsa44-ed25519@openssh.com`, the ML-DSA-44 + Ed25519 composite of
    /// [draft-miller-sshm-composite-sigs](https://www.ietf.org/archive/id/draft-miller-sshm-composite-sigs-01.html).
    MlDsa44Ed25519,
}

/**
 * Generate a new SSH key pair, for the provided key algorithm, returning
 * an [SshKeyData] struct containing the private key, public key, and key fingerprint,
 * with the private key in OpenSSH format.
 */
pub fn generate_sshkey(
    key_algorithm: KeyAlgorithm,
) -> Result<SshKeyData, error::KeyGenerationError> {
    let mut rng = bitwarden_random::rng();
    generate_sshkey_internal(key_algorithm, &mut rng)
}

fn generate_sshkey_internal<R: CryptoRng + ?Sized>(
    key_algorithm: KeyAlgorithm,
    rng: &mut R,
) -> Result<SshKeyData, error::KeyGenerationError> {
    let private_key = match key_algorithm {
        KeyAlgorithm::Ed25519 => ssh_key::PrivateKey::random(rng, Algorithm::Ed25519)
            .map_err(KeyGenerationError::KeyGeneration),
        KeyAlgorithm::Rsa3072 => create_rsa_key(rng, 3072),
        KeyAlgorithm::Rsa4096 => create_rsa_key(rng, 4096),
        KeyAlgorithm::EcdsaP256 => ssh_key::PrivateKey::random(
            rng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .map_err(KeyGenerationError::KeyGeneration),
        KeyAlgorithm::EcdsaP384 => ssh_key::PrivateKey::random(
            rng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
        )
        .map_err(KeyGenerationError::KeyGeneration),
        KeyAlgorithm::EcdsaP521 => ssh_key::PrivateKey::random(
            rng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
        )
        .map_err(KeyGenerationError::KeyGeneration),
        KeyAlgorithm::MlDsa44Ed25519 => ssh_key::PrivateKey::random(rng, Algorithm::MlDsa44Ed25519)
            .map_err(KeyGenerationError::KeyGeneration),
    }?;

    ssh_private_key_to_data(private_key).map_err(|_| KeyGenerationError::KeyConversion)
}

fn create_rsa_key<R: CryptoRng + ?Sized>(
    rng: &mut R,
    bits: usize,
) -> Result<ssh_key::PrivateKey, error::KeyGenerationError> {
    let rsa_keypair = ssh_key::private::RsaKeypair::random(rng, bits)
        .map_err(KeyGenerationError::KeyGeneration)?;
    let private_key =
        ssh_key::PrivateKey::new(ssh_key::private::KeypairData::from(rsa_keypair), "")
            .map_err(KeyGenerationError::KeyGeneration)?;
    Ok(private_key)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::KeyAlgorithm;
    use crate::generator::generate_sshkey_internal;

    #[test]
    fn generate_ssh_key_ed25519() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::Ed25519;
        let result = generate_sshkey_internal(key_algorithm, &mut rng);
        let target = include_str!("../resources/generator/ed25519_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_rsa3072() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::Rsa3072;
        let result = generate_sshkey_internal(key_algorithm, &mut rng);
        let target = include_str!("../resources/generator/rsa3072_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_rsa4096() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::Rsa4096;
        let result = generate_sshkey_internal(key_algorithm, &mut rng);
        let target = include_str!("../resources/generator/rsa4096_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_ecdsa_p256() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::EcdsaP256;
        let result = generate_sshkey_internal(key_algorithm, &mut rng);
        let target = include_str!("../resources/generator/ecdsa_p256_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_ecdsa_p384() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::EcdsaP384;
        let result = generate_sshkey_internal(key_algorithm, &mut rng);
        let target = include_str!("../resources/generator/ecdsa_p384_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_ecdsa_p521() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::EcdsaP521;
        let result = generate_sshkey_internal(key_algorithm, &mut rng);
        let target = include_str!("../resources/generator/ecdsa_p521_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_mldsa44_ed25519() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::MlDsa44Ed25519;
        let result = generate_sshkey_internal(key_algorithm, &mut rng);
        let target =
            include_str!("../resources/generator/mldsa44_ed25519_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    /// A generated composite key must survive a round trip through the OpenSSH private key format
    /// and still produce signatures its own public key accepts.
    #[test]
    fn mldsa44_ed25519_round_trip() {
        use signature::{Signer, Verifier};
        use ssh_key::Algorithm;

        use crate::import::import_key;

        const MESSAGE: &[u8] = b"bitwarden ssh agent";

        let mut rng = rand_chacha::ChaCha12Rng::from_seed([1u8; 32]);
        let generated = generate_sshkey_internal(KeyAlgorithm::MlDsa44Ed25519, &mut rng)
            .expect("generation should succeed");
        assert!(
            generated
                .public_key
                .starts_with("ssh-mldsa44-ed25519@openssh.com ")
        );

        let imported =
            import_key(generated.private_key.clone(), None).expect("import should succeed");
        assert_eq!(imported.public_key, generated.public_key);
        assert_eq!(imported.fingerprint, generated.fingerprint);

        let private_key = ssh_key::PrivateKey::from_openssh(&imported.private_key)
            .expect("re-imported key should parse");
        assert_eq!(private_key.algorithm(), Algorithm::MlDsa44Ed25519);

        // Trait-qualified: the inherent `sign`/`verify` on these types are the `sshsig` ones.
        let signature: ssh_key::Signature =
            Signer::try_sign(&private_key, MESSAGE).expect("signing should succeed");
        Verifier::verify(private_key.public_key(), MESSAGE, &signature)
            .expect("own signature should verify");

        let mut tampered = MESSAGE.to_vec();
        tampered[0] ^= 1;
        assert!(Verifier::verify(private_key.public_key(), &tampered, &signature).is_err());
    }
}
