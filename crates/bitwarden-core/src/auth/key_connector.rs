use bitwarden_crypto::{CryptoError, MasterKey, RsaKeyPair};
use bitwarden_encoding::B64;

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct KeyConnectorResponse {
    pub master_key: B64,
    pub encrypted_user_key: String,
    pub keys: RsaKeyPair,
}

pub(super) fn make_key_connector_keys() -> Result<KeyConnectorResponse, CryptoError> {
    let master_key = MasterKey::generate();
    let (user_key, encrypted_user_key) = master_key.make_user_key()?;
    let keys = user_key.make_key_pair()?;

    Ok(KeyConnectorResponse {
        master_key: master_key.to_base64(),
        encrypted_user_key: encrypted_user_key.to_string(),
        keys,
    })
}
