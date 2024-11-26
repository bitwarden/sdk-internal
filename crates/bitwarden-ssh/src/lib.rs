use error::KeyGenerationError;
use ssh_key::{rand_core::CryptoRngCore, Algorithm, HashAlg, LineEnding};

pub mod error;

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum KeyAlgorithm {
    Ed25519,
    Rsa3072,
    Rsa4096,
}

pub fn generate_sshkey(
    key_algorithm: KeyAlgorithm,
) -> Result<GenerateSshKeyResult, error::KeyGenerationError> {
    let rng = rand::thread_rng();
    generate_sshkey_internal(key_algorithm, rng)
}

fn generate_sshkey_internal(
    key_algorithm: KeyAlgorithm,
    mut rng: impl CryptoRngCore,
) -> Result<GenerateSshKeyResult, error::KeyGenerationError> {
    let key = match key_algorithm {
        KeyAlgorithm::Ed25519 => ssh_key::PrivateKey::random(&mut rng, Algorithm::Ed25519),
        KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            let bits = match key_algorithm {
                KeyAlgorithm::Rsa3072 => 3072,
                KeyAlgorithm::Rsa4096 => 4096,
                _ => unreachable!(),
            };

            let rsa_keypair = ssh_key::private::RsaKeypair::random(&mut rng, bits)
                .map_err(KeyGenerationError::KeyGenerationError)?;

            let private_key =
                ssh_key::PrivateKey::new(ssh_key::private::KeypairData::from(rsa_keypair), "")
                    .map_err(KeyGenerationError::KeyGenerationError)?;
            Ok(private_key)
        }
    }
    .map_err(KeyGenerationError::KeyGenerationError)?;

    let private_key_openssh = key
        .to_openssh(LineEnding::LF)
        .map_err(KeyGenerationError::KeyConversionError)?;
    Ok(GenerateSshKeyResult {
        private_key: private_key_openssh.to_string(),
        public_key: key.public_key().to_string(),
        key_fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
    })
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct GenerateSshKeyResult {
    pub private_key: String,
    pub public_key: String,
    pub key_fingerprint: String,
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::KeyAlgorithm;
    use crate::generate_sshkey_internal;

    #[test]
    fn generate_ssh_key_ed25519() {
        let rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::Ed25519;
        let result = generate_sshkey_internal(key_algorithm, rng);
        let target = include_str!("../tests/ed25519_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_rsa3072() {
        let rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::Rsa3072;
        let result = generate_sshkey_internal(key_algorithm, rng);
        let target = include_str!("../tests/rsa3072_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_rsa4096() {
        let rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::Rsa4096;
        let result = generate_sshkey_internal(key_algorithm, rng);
        let target = include_str!("../tests/rsa4096_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }
}
