use bitwarden_crypto::{
    CryptoError, EncString, EncryptionContext, KeyDecryptable, KeyEncryptable, NoContextBuilder, SymmetricCryptoKey
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SshKey {
    /// SSH private key (ed25519/rsa) in unencrypted openssh private key format [OpenSSH private key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
    pub private_key: EncString,
    /// SSH public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
    pub public_key: EncString,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`
    pub fingerprint: EncString,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SshKeyView {
    /// SSH private key (ed25519/rsa) in unencrypted openssh private key format [OpenSSH private key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
    pub private_key: String,
    /// SSH public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
    pub public_key: String,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`
    pub fingerprint: String,
}

impl<Context: EncryptionContext> KeyEncryptable<SymmetricCryptoKey, SshKey, Context> for SshKeyView {
    fn encrypt_with_key(self, key: &SymmetricCryptoKey, context: &Context) -> Result<SshKey, CryptoError> {
        Ok(SshKey {
            private_key: self.private_key.encrypt_with_key(key, context)?,
            public_key: self.public_key.encrypt_with_key(key, context)?,
            fingerprint: self.fingerprint.encrypt_with_key(key, context)?,
        })
    }
}

impl KeyDecryptable<SymmetricCryptoKey, SshKeyView, NoContextBuilder> for SshKey {
    fn decrypt_with_key(&self, key: &SymmetricCryptoKey, context_builder: &NoContextBuilder) -> Result<SshKeyView, CryptoError> {
        Ok(SshKeyView {
            private_key: self.private_key.decrypt_with_key(key, context_builder)?,
            public_key: self.public_key.decrypt_with_key(key, context_builder)?,
            fingerprint: self.fingerprint.decrypt_with_key(key, context_builder)?,
        })
    }
}
