use bitwarden_vault::SshKeyView;
use ed25519;
use pem_rfc7468::PemLabel;
use pkcs8::{DecodePrivateKey, PrivateKeyInfo, SecretDocument, der::Decode, pkcs5};
use ssh_key::private::{Ed25519Keypair, RsaKeypair};
#[cfg(feature = "ecdsa-keys")]
use ssh_key::sec1;

use crate::{error::SshKeyImportError, ssh_private_key_to_view};

/// Import a PKCS8 or OpenSSH encoded private key, and returns a decoded [SshKeyView],
/// with the public key and fingerprint, and the private key in OpenSSH format.
/// A password can be provided for encrypted keys.
/// # Returns
/// - [SshKeyImportError::PasswordRequired] if the key is encrypted and no password is provided
/// - [SshKeyImportError::WrongPassword] if the password provided is incorrect
/// - [SshKeyImportError::UnsupportedKeyType] if the key type is not supported
/// - [SshKeyImportError::Parsing] if the key is otherwise malformed and cannot be parsed
pub fn import_key(
    encoded_key: String,
    password: Option<String>,
) -> Result<SshKeyView, SshKeyImportError> {
    let label = pem_rfc7468::decode_label(encoded_key.as_bytes())
        .map_err(|_| SshKeyImportError::Parsing)?;

    match label {
        pkcs8::PrivateKeyInfo::<(), (), ()>::PEM_LABEL => import_pkcs8_key(encoded_key, None),
        pkcs8::EncryptedPrivateKeyInfo::<()>::PEM_LABEL => import_pkcs8_key(
            encoded_key,
            Some(password.ok_or(SshKeyImportError::PasswordRequired)?),
        ),
        ssh_key::PrivateKey::PEM_LABEL => import_openssh_key(encoded_key, password),
        _ => Err(SshKeyImportError::UnsupportedKeyType),
    }
}

fn import_pkcs8_key(
    encoded_key: String,
    password: Option<String>,
) -> Result<SshKeyView, SshKeyImportError> {
    let doc = if let Some(password) = password {
        SecretDocument::from_pkcs8_encrypted_pem(&encoded_key, password.as_bytes()).map_err(
            |err| match err {
                pkcs8::Error::EncryptedPrivateKey(pkcs5::Error::DecryptFailed) => {
                    SshKeyImportError::WrongPassword
                }
                _ => SshKeyImportError::Parsing,
            },
        )?
    } else {
        SecretDocument::from_pkcs8_pem(&encoded_key).map_err(|_| SshKeyImportError::Parsing)?
    };

    import_pkcs8_der_key(doc.as_bytes())
}

/// Import a DER encoded private key, and returns a decoded [SshKeyView]. This is primarily used for
/// importing SSH keys from other Credential Managers through Credential Exchange.
pub fn import_pkcs8_der_key(encoded_key: &[u8]) -> Result<SshKeyView, SshKeyImportError> {
    let private_key_info =
        PrivateKeyInfo::from_der(encoded_key).map_err(|_| SshKeyImportError::Parsing)?;

    let private_key = match private_key_info.algorithm.oid {
        ed25519::pkcs8::ALGORITHM_OID => {
            let private_key: ed25519::KeypairBytes = private_key_info
                .try_into()
                .map_err(|_| SshKeyImportError::Parsing)?;

            ssh_key::private::PrivateKey::from(Ed25519Keypair::from(&private_key.secret_key.into()))
        }
        rsa::pkcs1::ALGORITHM_OID => {
            let private_key: rsa::RsaPrivateKey = private_key_info
                .try_into()
                .map_err(|_| SshKeyImportError::Parsing)?;

            ssh_key::private::PrivateKey::from(
                RsaKeypair::try_from(private_key).map_err(|_| SshKeyImportError::Parsing)?,
            )
        }
        #[cfg(feature = "ecdsa-keys")]
        sec1::ALGORITHM_OID => import_ecdsa_pkcs8_der(encoded_key)?,
        _ => return Err(SshKeyImportError::UnsupportedKeyType),
    };

    ssh_private_key_to_view(private_key).map_err(|_| SshKeyImportError::Parsing)
}

fn import_openssh_key(
    encoded_key: String,
    password: Option<String>,
) -> Result<SshKeyView, SshKeyImportError> {
    let private_key =
        ssh_key::private::PrivateKey::from_openssh(&encoded_key).map_err(|err| match err {
            ssh_key::Error::AlgorithmUnknown | ssh_key::Error::AlgorithmUnsupported { .. } => {
                SshKeyImportError::UnsupportedKeyType
            }
            _ => SshKeyImportError::Parsing,
        })?;

    let private_key = if private_key.is_encrypted() {
        let password = password.ok_or(SshKeyImportError::PasswordRequired)?;
        private_key
            .decrypt(password.as_bytes())
            .map_err(|_| SshKeyImportError::WrongPassword)?
    } else {
        private_key
    };

    reject_ecdsa_import(&private_key)?;

    ssh_private_key_to_view(private_key).map_err(|_| SshKeyImportError::Parsing)
}

fn reject_ecdsa_import(key: &ssh_key::PrivateKey) -> Result<(), SshKeyImportError> {
    #[cfg(not(feature = "ecdsa-keys"))]
    if matches!(key.key_data(), ssh_key::private::KeypairData::Ecdsa(_)) {
        return Err(SshKeyImportError::UnsupportedKeyType);
    }
    let _ = key;
    Ok(())
}

#[cfg(feature = "ecdsa-keys")]
fn import_ecdsa_pkcs8_der(encoded_key: &[u8]) -> Result<ssh_key::PrivateKey, SshKeyImportError> {
    use pkcs8::DecodePrivateKey as _;

    if let Ok(sk) = p256::SecretKey::from_pkcs8_der(encoded_key) {
        let public_key = sk.public_key();
        let keypair = ssh_key::private::EcdsaKeypair::NistP256 {
            public: public_key.into(),
            private: ssh_key::private::EcdsaPrivateKey::from(sk),
        };
        return ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ecdsa(keypair), "")
            .map_err(|_| SshKeyImportError::Parsing);
    }
    if let Ok(sk) = p384::SecretKey::from_pkcs8_der(encoded_key) {
        let public_key = sk.public_key();
        let keypair = ssh_key::private::EcdsaKeypair::NistP384 {
            public: public_key.into(),
            private: ssh_key::private::EcdsaPrivateKey::from(sk),
        };
        return ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ecdsa(keypair), "")
            .map_err(|_| SshKeyImportError::Parsing);
    }
    if let Ok(sk) = p521::SecretKey::from_pkcs8_der(encoded_key) {
        let public_key = sk.public_key();
        let keypair = ssh_key::private::EcdsaKeypair::NistP521 {
            public: public_key.into(),
            private: ssh_key::private::EcdsaPrivateKey::from(sk),
        };
        return ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ecdsa(keypair), "")
            .map_err(|_| SshKeyImportError::Parsing);
    }
    Err(SshKeyImportError::UnsupportedKeyType)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_key_ed25519_openssh_unencrypted() {
        let private_key = include_str!("../resources/import/ed25519_openssh_unencrypted");
        let public_key = include_str!("../resources/import/ed25519_openssh_unencrypted.pub").trim();
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_ed25519_openssh_encrypted() {
        let private_key = include_str!("../resources/import/ed25519_openssh_encrypted");
        let public_key = include_str!("../resources/import/ed25519_openssh_encrypted.pub").trim();
        let result = import_key(private_key.to_string(), Some("password".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_openssh_unencrypted() {
        let private_key = include_str!("../resources/import/rsa_openssh_unencrypted");
        let public_key = include_str!("../resources/import/rsa_openssh_unencrypted.pub").trim();
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_openssh_encrypted() {
        let private_key = include_str!("../resources/import/rsa_openssh_encrypted");
        let public_key = include_str!("../resources/import/rsa_openssh_encrypted.pub").trim();
        let result = import_key(private_key.to_string(), Some("password".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_ed25519_pkcs8_unencrypted() {
        let private_key = include_str!("../resources/import/ed25519_pkcs8_unencrypted");
        let public_key = include_str!("../resources/import/ed25519_pkcs8_unencrypted.pub")
            .replace("testkey", "");
        let public_key = public_key.trim();
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_pkcs8_unencrypted() {
        let private_key = include_str!("../resources/import/rsa_pkcs8_unencrypted");
        // for whatever reason pkcs8 + rsa does not include the comment in the public key
        let public_key =
            include_str!("../resources/import/rsa_pkcs8_unencrypted.pub").replace("testkey", "");
        let public_key = public_key.trim();
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_pkcs8_encrypted() {
        let private_key = include_str!("../resources/import/rsa_pkcs8_encrypted");
        let public_key =
            include_str!("../resources/import/rsa_pkcs8_encrypted.pub").replace("testkey", "");
        let public_key = public_key.trim();
        let result = import_key(private_key.to_string(), Some("password".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_ed25519_openssh_encrypted_wrong_password() {
        let private_key = include_str!("../resources/import/ed25519_openssh_encrypted");
        let result = import_key(private_key.to_string(), Some("wrongpassword".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::WrongPassword);
    }

    #[test]
    fn import_non_key_error() {
        let result = import_key("not a key".to_string(), Some("".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::Parsing);
    }

    #[test]
    fn import_wrong_label_error() {
        let private_key = include_str!("../resources/import/wrong_label");
        let result = import_key(private_key.to_string(), Some("".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::UnsupportedKeyType);
    }

    #[cfg(not(feature = "ecdsa-keys"))]
    #[test]
    fn import_ecdsa_blocked() {
        let private_key = include_str!("../resources/import/ecdsa_openssh_unencrypted");
        let result = import_key(private_key.to_string(), Some("".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::UnsupportedKeyType);
    }

    #[cfg(feature = "ecdsa-keys")]
    #[test]
    fn import_ecdsa_p256_openssh_unencrypted() {
        let private_key = include_str!("../resources/import/ecdsa_openssh_unencrypted");
        let public_key = include_str!("../resources/import/ecdsa_openssh_unencrypted.pub").trim();
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[cfg(feature = "ecdsa-keys")]
    #[test]
    fn import_ecdsa_p384_openssh_unencrypted() {
        let private_key = include_str!("../resources/import/ecdsa_p384_openssh_unencrypted");
        let public_key =
            include_str!("../resources/import/ecdsa_p384_openssh_unencrypted.pub").trim();
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[cfg(feature = "ecdsa-keys")]
    #[test]
    fn import_ecdsa_p521_openssh_unencrypted() {
        let private_key = include_str!("../resources/import/ecdsa_p521_openssh_unencrypted");
        let public_key =
            include_str!("../resources/import/ecdsa_p521_openssh_unencrypted.pub").trim();
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_ed25519_putty() {
        let private_key = include_str!("../resources/import/ed25519_putty_openssh_unencrypted");
        let public_key =
            include_str!("../resources/import/ed25519_putty_openssh_unencrypted.pub").trim();
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_openssh_putty() {
        let private_key = include_str!("../resources/import/rsa_putty_openssh_unencrypted");
        let public_key =
            include_str!("../resources/import/rsa_putty_openssh_unencrypted.pub").trim();
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_pkcs8_putty() {
        let private_key = include_str!("../resources/import/rsa_putty_pkcs1_unencrypted");
        let result = import_key(private_key.to_string(), Some("".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::UnsupportedKeyType);
    }

    #[test]
    fn import_ed25519_key_regression_17028() {
        // https://github.com/bitwarden/clients/issues/17028#issuecomment-3455975763
        let private_key = include_str!("../resources/import/ed25519_regression_17028");
        let public_key = include_str!("../resources/import/ed25519_regression_17028.pub").trim();
        let result = import_key(private_key.to_string(), None).unwrap();
        assert_eq!(result.public_key, public_key);
    }
}
