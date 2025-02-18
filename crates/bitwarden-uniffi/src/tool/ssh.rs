use std::sync::Arc;

use bitwarden_vault::SshKeyView;

use crate::{
    error::{BitwardenError, Error},
    Client, Result,
};

#[derive(uniffi::Object)]
pub struct SshClient(pub Arc<Client>);

#[uniffi::export]
impl SshClient {
    pub fn generate_ssh_key(
        &self,
        key_algorithm: bitwarden_ssh::generator::KeyAlgorithm,
    ) -> Result<SshKeyView> {
        bitwarden_ssh::generator::generate_sshkey(key_algorithm)
            .map_err(|e| BitwardenError::E(Error::SshGeneration(e)))
    }

    pub fn import_ssh_key(
        &self,
        imported_key: String,
        password: Option<String>,
    ) -> Result<SshKeyView> {
        bitwarden_ssh::import::import_key(imported_key, password)
            .map_err(|e| BitwardenError::E(Error::SshImport(e)))
    }
}
