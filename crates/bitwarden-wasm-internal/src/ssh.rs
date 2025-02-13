use bitwarden_vault::SshKeyView;
use wasm_bindgen::prelude::*;

/// Generate a new SSH key pair
///
/// # Arguments
/// - `key_algorithm` - The algorithm to use for the key pair
///
/// # Returns
/// - `Ok(SshKey)` if the key was successfully generated
/// - `Err(KeyGenerationError)` if the key could not be generated
#[wasm_bindgen]
pub fn generate_ssh_key(
    key_algorithm: bitwarden_ssh::generator::KeyAlgorithm,
) -> Result<SshKeyView, bitwarden_ssh::error::KeyGenerationError> {
    bitwarden_ssh::generator::generate_sshkey(key_algorithm)
}

/// Convert a PCKS8 or OpenSSH encrypted or unencrypted private key
/// to an OpenSSH private key with public key and fingerprint
///
/// # Arguments
/// - `imported_key` - The private key to convert
/// - `password` - The password to use for decrypting the key
///
/// # Returns
/// - `Ok(SshKey)` if the key was successfully coneverted
/// - `Err(PasswordRequired)` if the key is encrypted and no password was provided
/// - `Err(WrongPassword)` if the password provided is incorrect
/// - `Err(ParsingError)` if the key could not be parsed
/// - `Err(UnsupportedKeyType)` if the key type is not supported
#[wasm_bindgen]
pub fn import_ssh_key(
    imported_key: &str,
    password: Option<String>,
) -> Result<SshKeyView, bitwarden_ssh::error::SshKeyImportError> {
    bitwarden_ssh::import::import_key(imported_key.to_string(), password)
}
