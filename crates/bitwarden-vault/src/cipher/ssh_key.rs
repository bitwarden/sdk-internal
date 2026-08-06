use bitwarden_api_api::models::CipherSshKeyModel;
use bitwarden_core::{
    key_management::{KeySlotIds, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, KeyStoreContext,
    PrimitiveEncryptable,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::cipher::CipherKind;
use crate::{Cipher, VaultParseError, cipher::cipher::CopyableCipherFields};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SshKey {
    /// SSH private key (ed25519/rsa) in unencrypted openssh private key format [OpenSSH private key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
    pub private_key: EncString,
    /// SSH public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6).
    pub public_key: Option<EncString>,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`.
    pub fingerprint: Option<EncString>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SshKeyView {
    /// SSH private key (ed25519/rsa) in unencrypted openssh private key format [OpenSSH private key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)
    pub private_key: String,
    /// SSH public key (ed25519/rsa) according to [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
    pub public_key: String,
    /// SSH fingerprint using SHA256 in the format: `SHA256:BASE64_ENCODED_FINGERPRINT`
    pub fingerprint: String,
}

impl From<bitwarden_ssh::SshKeyData> for SshKeyView {
    fn from(key: bitwarden_ssh::SshKeyData) -> Self {
        SshKeyView {
            private_key: key.private_key,
            public_key: key.public_key,
            fingerprint: key.fingerprint,
        }
    }
}

/// Derive the public key and fingerprint from an unencrypted OpenSSH private key.
///
/// Returns empty strings if the key cannot be parsed.
fn derive_public_key_and_fingerprint(private_key: &str) -> (String, String) {
    bitwarden_ssh::import::import_key(private_key.to_string(), None)
        .map(|data| (data.public_key, data.fingerprint))
        .unwrap_or_default()
}

impl CompositeEncryptable<KeySlotIds, SymmetricKeySlotId, SshKey> for SshKeyView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SshKey, CryptoError> {
        // Derive the public key/fingerprint from the private key when absent, so stored data is
        // always complete.
        let mut public_key = self.public_key.clone();
        let mut fingerprint = self.fingerprint.clone();
        if public_key.is_empty() || fingerprint.is_empty() {
            let (derived_public_key, derived_fingerprint) =
                derive_public_key_and_fingerprint(&self.private_key);
            if public_key.is_empty() {
                public_key = derived_public_key;
            }
            if fingerprint.is_empty() {
                fingerprint = derived_fingerprint;
            }
        }

        Ok(SshKey {
            private_key: self.private_key.encrypt(ctx, key)?,
            public_key: Some(public_key.encrypt(ctx, key)?),
            fingerprint: Some(fingerprint.encrypt(ctx, key)?),
        })
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, SshKeyView> for SshKey {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<SshKeyView, CryptoError> {
        let private_key: String = self.private_key.decrypt(ctx, key)?;

        match (&self.public_key, &self.fingerprint) {
            (Some(public_key), Some(fingerprint)) => Ok(SshKeyView {
                private_key,
                public_key: public_key.decrypt(ctx, key)?,
                fingerprint: fingerprint.decrypt(ctx, key)?,
            }),
            // Derive both from the private key when either is absent.
            _ => {
                let (public_key, fingerprint) = derive_public_key_and_fingerprint(&private_key);
                Ok(SshKeyView {
                    private_key,
                    public_key,
                    fingerprint,
                })
            }
        }
    }
}

impl CipherKind for SshKey {
    fn decrypt_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<String, CryptoError> {
        match &self.fingerprint {
            Some(fingerprint) => fingerprint.decrypt(ctx, key),
            // Derive the fingerprint from the private key when it isn't stored.
            None => {
                let private_key: String = self.private_key.decrypt(ctx, key)?;
                let (_, fingerprint) = derive_public_key_and_fingerprint(&private_key);
                Ok(fingerprint)
            }
        }
    }

    fn get_copyable_fields(&self, _: Option<&Cipher>) -> Vec<CopyableCipherFields> {
        [CopyableCipherFields::SshKey].into_iter().collect()
    }
}

impl TryFrom<CipherSshKeyModel> for SshKey {
    type Error = VaultParseError;

    fn try_from(ssh_key: CipherSshKeyModel) -> Result<Self, Self::Error> {
        Ok(Self {
            private_key: require!(EncString::try_from_optional(ssh_key.private_key)?),
            public_key: EncString::try_from_optional(ssh_key.public_key)?,
            fingerprint: EncString::try_from_optional(ssh_key.key_fingerprint)?,
        })
    }
}

impl From<SshKey> for CipherSshKeyModel {
    fn from(ssh_key: SshKey) -> Self {
        Self {
            private_key: Some(ssh_key.private_key.to_string()),
            public_key: ssh_key.public_key.map(|e| e.to_string()),
            key_fingerprint: ssh_key.fingerprint.map(|e| e.to_string()),
        }
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
        let key = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        let original_subtitle = "SHA256:1JjFjvPRkj1Gbf2qRP1dgHiIzEuNAEvp+92x99jw3K0".to_string();
        let fingerprint_encrypted = original_subtitle.to_owned().encrypt(&mut ctx, key).unwrap();
        let private_key_encrypted = "".to_string().encrypt(&mut ctx, key).unwrap();
        let public_key_encrypted = "".to_string().encrypt(&mut ctx, key).unwrap();

        let ssh_key = SshKey {
            private_key: private_key_encrypted,
            public_key: Some(public_key_encrypted),
            fingerprint: Some(fingerprint_encrypted),
        };

        assert_eq!(
            ssh_key.decrypt_subtitle(&mut ctx, key).unwrap(),
            original_subtitle
        );
    }

    #[test]
    fn test_deserialize_missing_public_key_and_fingerprint() {
        // A cipher with only a private key deserializes with the missing fields as None.
        let absent = r#"{"privateKey":"2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE="}"#;
        let ssh_key: SshKey = serde_json::from_str(absent).unwrap();
        assert!(ssh_key.public_key.is_none());
        assert!(ssh_key.fingerprint.is_none());

        let null = r#"{"privateKey":"2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=","publicKey":null,"fingerprint":null}"#;
        let ssh_key: SshKey = serde_json::from_str(null).unwrap();
        assert!(ssh_key.public_key.is_none());
        assert!(ssh_key.fingerprint.is_none());
    }

    #[test]
    fn test_decrypt_unparseable_private_key_falls_back_to_empty() {
        // An absent public key/fingerprint with an unparseable private key decrypts to empty.
        let key = SymmetricCryptoKey::try_from("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        let key = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        let ssh_key = SshKey {
            private_key: "the-private-key"
                .to_string()
                .encrypt(&mut ctx, key)
                .unwrap(),
            public_key: None,
            fingerprint: None,
        };

        let view = ssh_key.decrypt(&mut ctx, key).unwrap();
        assert_eq!(view.private_key, "the-private-key");
        assert_eq!(view.public_key, "");
        assert_eq!(view.fingerprint, "");
    }

    #[test]
    fn test_decrypt_derives_missing_public_key_and_fingerprint() {
        // A cipher with only a private key decrypts to a complete view, deriving the public key
        // and fingerprint.
        let key = SymmetricCryptoKey::try_from("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        let key = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        // A real key whose public key and fingerprint are derivable from the private key.
        let generated = bitwarden_ssh::generator::generate_sshkey(
            bitwarden_ssh::generator::KeyAlgorithm::Ed25519,
        )
        .unwrap();

        let ssh_key = SshKey {
            private_key: generated
                .private_key
                .clone()
                .encrypt(&mut ctx, key)
                .unwrap(),
            public_key: None,
            fingerprint: None,
        };

        let view = ssh_key.decrypt(&mut ctx, key).unwrap();
        assert_eq!(view.private_key, generated.private_key);
        assert_eq!(view.public_key, generated.public_key);
        assert_eq!(view.fingerprint, generated.fingerprint);
        assert!(!view.public_key.is_empty());
        assert!(!view.fingerprint.is_empty());

        // The list subtitle derives the same fingerprint.
        assert_eq!(
            ssh_key.decrypt_subtitle(&mut ctx, key).unwrap(),
            generated.fingerprint
        );
    }

    #[test]
    fn test_encrypt_composite_derives_missing_fields() {
        // Write path: a view lacking the public key/fingerprint must persist derived values.
        let key = SymmetricCryptoKey::try_from("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        let key = SymmetricKeySlotId::User;
        let mut ctx = key_store.context();

        let generated = bitwarden_ssh::generator::generate_sshkey(
            bitwarden_ssh::generator::KeyAlgorithm::Ed25519,
        )
        .unwrap();

        let view = SshKeyView {
            private_key: generated.private_key.clone(),
            public_key: String::new(),
            fingerprint: String::new(),
        };

        let encrypted = view.encrypt_composite(&mut ctx, key).unwrap();
        assert!(encrypted.public_key.is_some());
        assert!(encrypted.fingerprint.is_some());

        let decrypted = encrypted.decrypt(&mut ctx, key).unwrap();
        assert_eq!(decrypted.public_key, generated.public_key);
        assert_eq!(decrypted.fingerprint, generated.fingerprint);
    }

    #[test]
    fn test_get_copyable_fields_sshkey() {
        let ssh_key = SshKey {
            private_key: "2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap(),
            public_key: Some("2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap()),
            fingerprint: Some("2.tMIugb6zQOL+EuOizna1wQ==|W5dDLoNJtajN68yeOjrr6w==|qS4hwJB0B0gNLI0o+jxn+sKMBmvtVgJCRYNEXBZoGeE=".parse().unwrap()),
        };

        let copyable_fields = ssh_key.get_copyable_fields(None);
        assert_eq!(copyable_fields, vec![CopyableCipherFields::SshKey]);
    }
}
