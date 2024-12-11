use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_ssh_key(
    key_algorithm: bitwarden_ssh::KeyAlgorithm,
) -> Result<bitwarden_ssh::GenerateSshKeyResult, bitwarden_ssh::error::KeyGenerationError> {
    bitwarden_ssh::generate_sshkey(key_algorithm)
}
