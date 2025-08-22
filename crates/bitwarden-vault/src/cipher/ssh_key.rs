use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, KeyStoreContext,
    PrimitiveEncryptable,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::cipher::CipherKind;
use crate::{cipher::cipher::CopyableCipherFields, Cipher};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SshKey {
    /// SSH private key (ed25519/rsa) in unencrypted OpenSSH private key format [OpenSSH private key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key).
    /// For encrypted imports, this may be empty; see `originalPrivateKey`.
    pub private_key: EncString,
    /// SSH public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
    pub public_key: EncString,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`
    pub fingerprint: EncString,
    /// Original SSH private key as provided during import (PEM). If the key was encrypted, this preserves the encrypted PEM verbatim.
    pub original_private_key: Option<EncString>,
    /// Indicates whether the original_private_key was encrypted at import time.
    pub is_encrypted: bool,
    /// Optional stored passphrase for the SSH private key (if user opted-in).
    pub ssh_key_passphrase: Option<EncString>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SshKeyView {
    /// Preferred SSH private key material to display/copy. For unencrypted keys this is an OpenSSH PEM.
    /// For encrypted imports this may be empty; see `original_private_key`.
    pub private_key: String,
    /// SSH public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
    pub public_key: String,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`
    pub fingerprint: String,
    /// Original SSH private key as provided during import (PEM). If the key was encrypted, this preserves the encrypted PEM verbatim.
    pub original_private_key: Option<String>,
    /// Indicates whether the original_private_key was encrypted at import time.
    pub is_encrypted: bool,
    /// Optional stored passphrase for the SSH private key (if user opted-in).
    pub ssh_key_passphrase: Option<String>,
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, SshKey> for SshKeyView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<SshKey, CryptoError> {
        Ok(SshKey {
            private_key: self.private_key.encrypt(ctx, key)?,
            public_key: self.public_key.encrypt(ctx, key)?,
            fingerprint: self.fingerprint.encrypt(ctx, key)?,
            original_private_key: self.original_private_key.encrypt(ctx, key)?,
            is_encrypted: self.is_encrypted,
            ssh_key_passphrase: self.ssh_key_passphrase.encrypt(ctx, key)?,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, SshKeyView> for SshKey {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<SshKeyView, CryptoError> {
        Ok(SshKeyView {
            private_key: self.private_key.decrypt(ctx, key)?,
            public_key: self.public_key.decrypt(ctx, key)?,
            fingerprint: self.fingerprint.decrypt(ctx, key)?,
            original_private_key: self.original_private_key.decrypt(ctx, key)?,
            is_encrypted: self.is_encrypted,
            ssh_key_passphrase: self.ssh_key_passphrase.decrypt(ctx, key)?,
        })
    }
}

impl CipherKind for SshKey {
    fn decrypt_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<String, CryptoError> {
        self.fingerprint.decrypt(ctx, key)
    }

    fn get_copyable_fields(&self, _: Option<&Cipher>) -> Vec<CopyableCipherFields> {
        [CopyableCipherFields::SshKey].into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::SymmetricCryptoKey;

    use super::*;
    use crate::cipher::cipher::CopyableCipherFields;

    #[test]
    fn test_subtitle_ssh_key() {
        let key = SymmetricCryptoKey::try_from("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        let key = SymmetricKeyId::User;
        let mut ctx = key_store.context();

        let original_subtitle = "SHA256:1JjFjvPRkj1Gbf2qRP1dgHiIzEuNAEvp+92x99jw3K0".to_string();
        let fingerprint_encrypted = original_subtitle.to_owned().encrypt(&mut ctx, key).unwrap();
        let private_key_encrypted = "".to_string().encrypt(&mut ctx, key).unwrap();
        let public_key_encrypted = "".to_string().encrypt(&mut ctx, key).unwrap();

        let ssh_key = SshKey {
            private_key: private_key_encrypted,
            public_key: public_key_encrypted,
            fingerprint: fingerprint_encrypted,
            original_private_key: None,
            is_encrypted: false,
            ssh_key_passphrase: None,
        };

        assert_eq!(
            ssh_key.decrypt_subtitle(&mut ctx, key).unwrap(),
            original_subtitle
        );
    }

    #[test]
    fn test_get_copyable_fields_sshkey() {
        let ssh_key = SshKey {
            private_key: "2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap(),
            public_key: "2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap(),
            fingerprint: "2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap(),
            original_private_key: None,
            is_encrypted: false,
            ssh_key_passphrase: None,
        };

        let copyable_fields = ssh_key.get_copyable_fields(None);
        assert_eq!(copyable_fields, vec![CopyableCipherFields::SshKey]);
    }
}
