use bitwarden_core::key_management::{AsymmetricKeyRef, SymmetricKeyRef};
use bitwarden_crypto::{
    service::CryptoServiceContext, CryptoError, Decryptable, EncString, Encryptable,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SshKey {
    /// SSH private key (ed25519/rsa) in unencrypted openssh private key format [OpenSSH private key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
    pub private_key: Option<EncString>,
    /// SSH public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
    pub public_key: Option<EncString>,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`
    pub fingerprint: Option<EncString>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SshKeyView {
    /// SSH private key (ed25519/rsa) in unencrypted openssh private key format [OpenSSH private key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
    pub private_key: Option<String>,
    /// SSH public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
    pub public_key: Option<String>,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`
    pub fingerprint: Option<String>,
}

impl Encryptable<SymmetricKeyRef, AsymmetricKeyRef, SymmetricKeyRef, SshKey> for SshKeyView {
    fn encrypt(
        &self,
        ctx: &mut CryptoServiceContext<SymmetricKeyRef, AsymmetricKeyRef>,
        key: SymmetricKeyRef,
    ) -> Result<SshKey, CryptoError> {
        Ok(SshKey {
            private_key: self.private_key.encrypt(ctx, key).ok().flatten(),
            public_key: self.public_key.encrypt(ctx, key).ok().flatten(),
            fingerprint: self.fingerprint.encrypt(ctx, key).ok().flatten(),
        })
    }
}

impl Decryptable<SymmetricKeyRef, AsymmetricKeyRef, SymmetricKeyRef, SshKeyView> for SshKey {
    fn decrypt(
        &self,
        ctx: &mut CryptoServiceContext<SymmetricKeyRef, AsymmetricKeyRef>,
        key: SymmetricKeyRef,
    ) -> Result<SshKeyView, CryptoError> {
        Ok(SshKeyView {
            private_key: self.private_key.decrypt(ctx, key).ok().flatten(),
            public_key: self.public_key.decrypt(ctx, key).ok().flatten(),
            fingerprint: self.fingerprint.decrypt(ctx, key).ok().flatten(),
        })
    }
}
