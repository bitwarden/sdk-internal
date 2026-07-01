use bitwarden_vault::SshKeyView;

use crate::Result;

#[derive(uniffi::Object)]
pub struct SshClient();

#[uniffi::export]
impl SshClient {
    pub fn generate_ssh_key(
        &self,
        key_algorithm: bitwarden_ssh::generator::KeyAlgorithm,
    ) -> Result<SshKeyView> {
        bitwarden_ssh::generator::generate_sshkey(key_algorithm).map_err(Into::into)
    }

    pub fn import_ssh_key(
        &self,
        imported_key: String,
        password: Option<String>,
    ) -> Result<SshKeyView> {
        bitwarden_ssh::import::import_key(imported_key, password).map_err(Into::into)
    }
}
