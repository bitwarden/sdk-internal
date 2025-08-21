use bitwarden_vault::SshKeyView;
use ed25519;
use pem_rfc7468::PemLabel;
use pkcs8::{der::Decode, pkcs5, DecodePrivateKey, PrivateKeyInfo, SecretDocument};
use ssh_key::private::{Ed25519Keypair, RsaKeypair};

use crate::{error::SshKeyImportError, ssh_private_key_to_view};

/// Import a PKCS8 or OpenSSH encoded private key, and returns a decoded [SshKeyView],
/// with the public key and fingerprint, and the private key in OpenSSH format.
/// A password can be provided for encrypted keys.
/// # Returns
/// - [SshKeyImportError::PasswordRequired] if the key is encrypted and no password is provided
/// - [SshKeyImportError::WrongPassword] if the password provided is incorrect
/// - [SshKeyImportError::UnsupportedKeyType] if the key type is not supported
/// - [SshKeyImportError::ParsingError] if the key is otherwise malformed and cannot be parsed
pub fn import_key(
    encoded_key: String,
    password: Option<String>,
) -> Result<SshKeyView, SshKeyImportError> {
    let label = pem_rfc7468::decode_label(encoded_key.as_bytes())
        .map_err(|_| SshKeyImportError::ParsingError)?;

    match label {
        pkcs8::PrivateKeyInfo::PEM_LABEL => import_pkcs8_key(encoded_key, None),
        pkcs8::EncryptedPrivateKeyInfo::PEM_LABEL => import_pkcs8_key(
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
                _ => SshKeyImportError::ParsingError,
            },
        )?
    } else {
        SecretDocument::from_pkcs8_pem(&encoded_key).map_err(|_| SshKeyImportError::ParsingError)?
    };

    import_pkcs8_der_key(doc.as_bytes())
}

/// Import a DER encoded private key, and returns a decoded [SshKeyView]. This is primarily used for
/// importing SSH keys from other Credential Managers through Credential Exchange.
pub fn import_pkcs8_der_key(encoded_key: &[u8]) -> Result<SshKeyView, SshKeyImportError> {
    let private_key_info =
        PrivateKeyInfo::from_der(encoded_key).map_err(|_| SshKeyImportError::ParsingError)?;

    let private_key = match private_key_info.algorithm.oid {
        ed25519::pkcs8::ALGORITHM_OID => {
            let private_key: ed25519::KeypairBytes = private_key_info
                .try_into()
                .map_err(|_| SshKeyImportError::ParsingError)?;

            ssh_key::private::PrivateKey::from(Ed25519Keypair::from(&private_key.secret_key.into()))
        }
        rsa::pkcs1::ALGORITHM_OID => {
            let private_key: rsa::RsaPrivateKey = private_key_info
                .try_into()
                .map_err(|_| SshKeyImportError::ParsingError)?;

            ssh_key::private::PrivateKey::from(
                RsaKeypair::try_from(private_key).map_err(|_| SshKeyImportError::ParsingError)?,
            )
        }
        _ => return Err(SshKeyImportError::UnsupportedKeyType),
    };

    ssh_private_key_to_view(private_key).map_err(|_| SshKeyImportError::ParsingError)
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
            _ => SshKeyImportError::ParsingError,
        })?;

    let private_key = if private_key.is_encrypted() {
        let password = password.ok_or(SshKeyImportError::PasswordRequired)?;
        private_key
            .decrypt(password.as_bytes())
            .map_err(|_| SshKeyImportError::WrongPassword)?
    } else {
        private_key
    };

    ssh_private_key_to_view(private_key).map_err(|_| SshKeyImportError::ParsingError)
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
        assert_eq!(result.unwrap_err(), SshKeyImportError::ParsingError);
    }

    #[test]
    fn import_wrong_label_error() {
        let private_key = include_str!("../resources/import/wrong_label");
        let result = import_key(private_key.to_string(), Some("".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::UnsupportedKeyType);
    }

    #[test]
    fn import_ecdsa_error() {
        let private_key = include_str!("../resources/import/ecdsa_openssh_unencrypted");
        let result = import_key(private_key.to_string(), Some("".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::UnsupportedKeyType);
    }

    // Putty-exported keys should be supported, but are not due to a parser incompatibility.
    // Should this test start failing, please change it to expect a correct key, and
    // make sure the documentation support for putty-exported keys this is updated.
    // https://bitwarden.atlassian.net/browse/PM-14989
    #[test]
    fn import_key_ed25519_putty() {
        let private_key = include_str!("../resources/import/ed25519_putty_openssh_unencrypted");
        let result = import_key(private_key.to_string(), Some("".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::ParsingError);
    }

    // Putty-exported keys should be supported, but are not due to a parser incompatibility.
    // Should this test start failing, please change it to expect a correct key, and
    // make sure the documentation support for putty-exported keys this is updated.
    // https://bitwarden.atlassian.net/browse/PM-14989
    #[test]
    fn import_key_rsa_openssh_putty() {
        let private_key = include_str!("../resources/import/rsa_putty_openssh_unencrypted");
        let result = import_key(private_key.to_string(), Some("".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::ParsingError);
    }

    #[test]
    fn import_key_rsa_pkcs8_putty() {
        let private_key = include_str!("../resources/import/rsa_putty_pkcs1_unencrypted");
        let result = import_key(private_key.to_string(), Some("".to_string()));
        assert_eq!(result.unwrap_err(), SshKeyImportError::UnsupportedKeyType);
    }
}
