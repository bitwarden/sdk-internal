pub mod error;
pub mod generator;
pub mod import;

use error::SshKeyExportError;
use pkcs8::LineEnding;
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PrivateKey};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SshKey {
    /// The private key in OpenSSH format
    pub private_key: String,
    pub public_key: String,
    pub key_fingerprint: String,
}

impl TryFrom<PrivateKey> for SshKey {
    type Error = SshKeyExportError;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        let private_key_openssh = value
            .to_openssh(LineEnding::LF)
            .map_err(|_| SshKeyExportError::KeyConversionError)?;

        Ok(SshKey {
            private_key: private_key_openssh.to_string(),
            public_key: value.public_key().to_string(),
            key_fingerprint: value.fingerprint(HashAlg::Sha256).to_string(),
        })
    }
}
