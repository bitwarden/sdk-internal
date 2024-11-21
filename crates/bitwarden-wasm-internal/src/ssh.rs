use bitwarden_ssh;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub enum KeyAlgorithm {
    Ed25519,
    Rsa3072,
    Rsa4096,
}

// impl conversion
impl Into<bitwarden_ssh::KeyAlgorithm> for KeyAlgorithm {
    fn into(self) -> bitwarden_ssh::KeyAlgorithm {
        match self {
            KeyAlgorithm::Ed25519 => bitwarden_ssh::KeyAlgorithm::Ed25519,
            KeyAlgorithm::Rsa3072 => bitwarden_ssh::KeyAlgorithm::Rsa3072,
            KeyAlgorithm::Rsa4096 => bitwarden_ssh::KeyAlgorithm::Rsa4096,
        }
    }
}

#[wasm_bindgen]
pub struct SshKey {
    private_key: String,
    public_key: String,
    key_fingerprint: String,
}

impl From<bitwarden_ssh::models::SshKey> for SshKey {
    fn from(key: bitwarden_ssh::models::SshKey) -> Self {
        SshKey {
            private_key: key.private_key,
            public_key: key.public_key,
            key_fingerprint: key.key_fingerprint,
        }
    }
}

impl SshKey {
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn key_fingerprint(&self) -> &str {
        &self.key_fingerprint
    }
}

#[wasm_bindgen]
pub fn generate_ssh_key(
    key_algorithm: KeyAlgorithm,
) -> Result<SshKey, bitwarden_ssh::error::KeyGenerationError> {
    bitwarden_ssh::generate_keypair(key_algorithm.into()).map(|key| SshKey::from(key))
}
