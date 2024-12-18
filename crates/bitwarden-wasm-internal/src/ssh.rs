use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_ssh_key(
    key_algorithm: bitwarden_ssh::generator::KeyAlgorithm,
) -> Result<bitwarden_ssh::SshKey, bitwarden_ssh::error::KeyGenerationError> {
    bitwarden_ssh::generator::generate_sshkey(key_algorithm)
}

#[wasm_bindgen]
pub fn import_ssh_key(
    imported_key: &str,
    password: Option<String>,
) -> Result<bitwarden_ssh::SshKey, bitwarden_ssh::error::SshKeyImportError> {
    bitwarden_ssh::import::import_key(imported_key.to_string(), password)
}
