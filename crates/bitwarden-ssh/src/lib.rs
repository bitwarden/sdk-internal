pub mod error;
pub mod generator;
pub mod import;

use error::SshKeyImportError;
use pkcs8::LineEnding;
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PrivateKey};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SshKey {
    pub private_key: String,
    pub public_key: String,
    pub key_fingerprint: String,
}

impl TryFrom<PrivateKey> for SshKey {
    type Error = SshKeyImportError;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        let private_key_openssh = value
            .to_openssh(LineEnding::LF)
            .map_err(|_| SshKeyImportError::ParsingError)?;

        Ok(SshKey {
            private_key: private_key_openssh.to_string(),
            public_key: value.public_key().to_string(),
            key_fingerprint: value.fingerprint(HashAlg::Sha256).to_string(),
        })
    }
}
