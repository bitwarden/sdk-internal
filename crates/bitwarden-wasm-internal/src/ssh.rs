use bitwarden_ssh;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub enum KeyAlgorithm {
    Ed25519,
    Rsa3072,
    Rsa4096,
}

// impl conversion
impl From<KeyAlgorithm> for bitwarden_ssh::KeyAlgorithm {
    fn from(key_algorithm: KeyAlgorithm) -> Self {
        match key_algorithm {
            KeyAlgorithm::Ed25519 => bitwarden_ssh::KeyAlgorithm::Ed25519,
            KeyAlgorithm::Rsa3072 => bitwarden_ssh::KeyAlgorithm::Rsa3072,
            KeyAlgorithm::Rsa4096 => bitwarden_ssh::KeyAlgorithm::Rsa4096,
        }
    }
}

#[wasm_bindgen]
pub fn generate_ssh_key(
    key_algorithm: KeyAlgorithm,
) -> Result<bitwarden_ssh::GenerateKeypairResult, bitwarden_ssh::error::KeyGenerationError> {
    bitwarden_ssh::generate_keypair(key_algorithm.into())
}
