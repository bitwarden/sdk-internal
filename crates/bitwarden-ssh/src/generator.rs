use bitwarden_vault::SshKeyView;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, rand_core::CryptoRngCore};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{
    error::{self, KeyGenerationError},
    ssh_private_key_to_view,
};

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyAlgorithm {
    Ed25519,
    Rsa3072,
    Rsa4096,
}

/**
 * Generate a new SSH key pair, for the provided key algorithm, returning
 * an [SshKeyView] struct containing the private key, public key, and key fingerprint,
 * with the private key in OpenSSH format.
 */
pub fn generate_sshkey(
    key_algorithm: KeyAlgorithm,
) -> Result<SshKeyView, error::KeyGenerationError> {
    let rng = rand::thread_rng();
    generate_sshkey_internal(key_algorithm, rng)
}

fn generate_sshkey_internal(
    key_algorithm: KeyAlgorithm,
    mut rng: impl CryptoRngCore,
) -> Result<SshKeyView, error::KeyGenerationError> {
    let private_key = match key_algorithm {
        KeyAlgorithm::Ed25519 => ssh_key::PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .map_err(KeyGenerationError::KeyGeneration),
        KeyAlgorithm::Rsa3072 => create_rsa_key(&mut rng, 3072),
        KeyAlgorithm::Rsa4096 => create_rsa_key(&mut rng, 4096),
    }?;

    ssh_private_key_to_view(private_key).map_err(|_| KeyGenerationError::KeyConversion)
}

fn create_rsa_key(
    mut rng: impl CryptoRngCore,
    bits: usize,
) -> Result<ssh_key::PrivateKey, error::KeyGenerationError> {
    let rsa_keypair = ssh_key::private::RsaKeypair::random(&mut rng, bits)
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
        let rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::Ed25519;
        let result = generate_sshkey_internal(key_algorithm, rng);
        let target = include_str!("../resources/generator/ed25519_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_rsa3072() {
        let rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::Rsa3072;
        let result = generate_sshkey_internal(key_algorithm, rng);
        let target = include_str!("../resources/generator/rsa3072_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }

    #[test]
    fn generate_ssh_key_rsa4096() {
        let rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let key_algorithm = KeyAlgorithm::Rsa4096;
        let result = generate_sshkey_internal(key_algorithm, rng);
        let target = include_str!("../resources/generator/rsa4096_key").replace("\r\n", "\n");
        assert_eq!(result.unwrap().private_key, target);
    }
}
