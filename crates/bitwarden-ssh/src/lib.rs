use error::KeyGenerationError;
use ssh_key::{rand_core::CryptoRngCore, Algorithm, HashAlg, LineEnding};

pub mod error;
pub mod models;

pub enum KeyAlgorithm {
    Ed25519,
    Rsa3072,
    Rsa4096,
}

pub fn generate_keypair(
    key_algorithm: KeyAlgorithm,
) -> Result<models::SshKey, error::KeyGenerationError> {
    let rng = rand::thread_rng();
    generate_keypair_internal(key_algorithm, rng)
}

fn generate_keypair_internal(
    key_algorithm: KeyAlgorithm,
    mut rng: impl CryptoRngCore,
) -> Result<models::SshKey, error::KeyGenerationError> {
    let key = match key_algorithm {
        KeyAlgorithm::Ed25519 => ssh_key::PrivateKey::random(&mut rng, Algorithm::Ed25519),
        KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            let bits = match key_algorithm {
                KeyAlgorithm::Rsa3072 => 3072,
                KeyAlgorithm::Rsa4096 => 4096,
                _ => unreachable!(),
            };

            let rsa_keypair = ssh_key::private::RsaKeypair::random(&mut rng, bits)
                .map_err(|e| KeyGenerationError::KeyGenerationError(e.to_string()))?;

            let private_key =
                ssh_key::PrivateKey::new(ssh_key::private::KeypairData::from(rsa_keypair), "")
                    .map_err(|e| KeyGenerationError::KeyGenerationError(e.to_string()))?;
            Ok(private_key)
        }
    }
    .map_err(|e| KeyGenerationError::KeyGenerationError(e.to_string()))?;

    let private_key_openssh = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| KeyGenerationError::KeyConversionError(e.to_string()))?;
    Ok(models::SshKey {
        private_key: private_key_openssh.to_string(),
        public_key: key.public_key().to_string(),
        key_fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
    })
}
