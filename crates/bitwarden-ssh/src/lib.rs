#![doc = include_str!("../README.md")]

#[allow(missing_docs)]
pub mod error;
mod export;
pub use export::export_pkcs8_der_key;
#[allow(missing_docs)]
pub mod generator;
#[allow(missing_docs)]
pub mod import;

use error::SshKeyExportError;
use pkcs8::LineEnding;
use ssh_key::{HashAlg, PrivateKey};

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// Decoded SSH key material returned by this crate's import/generate functions.
#[derive(Debug)]
pub struct SshKeyData {
    /// SSH private key in unencrypted OpenSSH format.
    pub private_key: String,
    /// SSH public key according to RFC 4253.
    pub public_key: String,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`.
    pub fingerprint: String,
}

fn ssh_private_key_to_data(value: PrivateKey) -> Result<SshKeyData, SshKeyExportError> {
    let private_key_openssh = value
        .to_openssh(LineEnding::LF)
        .map_err(|_| SshKeyExportError::KeyConversion)?;

    Ok(SshKeyData {
        private_key: private_key_openssh.to_string(),
        public_key: value.public_key().to_string(),
        fingerprint: value.fingerprint(HashAlg::Sha256).to_string(),
    })
}
