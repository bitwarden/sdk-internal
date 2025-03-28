#![doc = include_str!("../README.md")]

pub mod error;
pub mod generator;
pub mod import;

use bitwarden_vault::SshKeyView;
use error::SshKeyExportError;
use pkcs8::LineEnding;
use ssh_key::{HashAlg, PrivateKey};

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

fn ssh_private_key_to_view(value: PrivateKey) -> Result<SshKeyView, SshKeyExportError> {
    let private_key_openssh = value
        .to_openssh(LineEnding::LF)
        .map_err(|_| SshKeyExportError::KeyConversionError)?;

    Ok(SshKeyView {
        private_key: private_key_openssh.to_string(),
        public_key: value.public_key().to_string(),
        fingerprint: value.fingerprint(HashAlg::Sha256).to_string(),
    })
}
