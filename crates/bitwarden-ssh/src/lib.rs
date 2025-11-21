#![doc = include_str!("../README.md")]

#[expect(missing_docs)]
pub mod error;
mod export;
pub use export::export_pkcs8_der_key;
#[expect(missing_docs)]
pub mod generator;
#[expect(missing_docs)]
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
        .map_err(|_| SshKeyExportError::KeyConversion)?;

    Ok(SshKeyView {
        private_key: private_key_openssh.to_string(),
        public_key: value.public_key().to_string(),
        fingerprint: value.fingerprint(HashAlg::Sha256).to_string(),
    })
}
