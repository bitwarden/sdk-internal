use bitwarden_vault::SshKeyView;
use ed25519;
use pem_rfc7468::PemLabel;
use pkcs8::{der::Decode, pkcs5, DecodePrivateKey, PrivateKeyInfo, SecretDocument};
use ssh_key::private::{Ed25519Keypair, RsaKeypair};
use ssh_key::HashAlg;
use pkcs8::LineEnding;

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
    // Load the PKCS#8 document (decrypt if necessary)
    let (doc, was_encrypted) = if let Some(ref pw) = password {
        (
            SecretDocument::from_pkcs8_encrypted_pem(&encoded_key, pw.as_bytes()).map_err(
                |err| match err {
                    pkcs8::Error::EncryptedPrivateKey(pkcs5::Error::DecryptFailed) => {
                        SshKeyImportError::WrongPassword
                    }
                    _ => SshKeyImportError::ParsingError,
                },
            )?,
            true,
        )
    } else {
        (
            SecretDocument::from_pkcs8_pem(&encoded_key)
                .map_err(|_| SshKeyImportError::ParsingError)?,
            false,
        )
    };

    // Reuse existing DER importer to compute public key and fingerprint
    let base = import_pkcs8_der_key(doc.as_bytes())?;

    // Preserve original PEM for round-trip fidelity; mark encryption status and passphrase (if provided)
    Ok(SshKeyView {
        private_key: if was_encrypted {
            encoded_key.clone()
        } else {
            base.private_key
        },
        public_key: base.public_key,
        fingerprint: base.fingerprint,
        original_private_key: Some(encoded_key),
        is_encrypted: was_encrypted,
        ssh_key_passphrase: if was_encrypted { password } else { None },
    })
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
    // Parse the original OpenSSH PEM to determine encryption and to compute pub/fingerprint.
    let parsed =
        ssh_key::private::PrivateKey::from_openssh(&encoded_key).map_err(|err| match err {
            ssh_key::Error::AlgorithmUnknown | ssh_key::Error::AlgorithmUnsupported { .. } => {
                SshKeyImportError::UnsupportedKeyType
            }
            _ => SshKeyImportError::ParsingError,
        })?;

    if parsed.is_encrypted() {
        // Encrypted: require password to decrypt for computing public key and fingerprint,
        // but preserve the original PEM verbatim for storage/export.
        let password = password.ok_or(SshKeyImportError::PasswordRequired)?;
        let decrypted = parsed
            .decrypt(password.as_bytes())
            .map_err(|_| SshKeyImportError::WrongPassword)?;

        let public_key = decrypted.public_key().to_string();
        let fingerprint = decrypted.fingerprint(HashAlg::Sha256).to_string();

        Ok(SshKeyView {
            private_key: encoded_key.clone(),
            public_key,
            fingerprint,
            original_private_key: Some(encoded_key),
            is_encrypted: true,
            ssh_key_passphrase: Some(password),
        })
    } else {
        // Unencrypted: compute public key and fingerprint as-is, preserve original PEM verbatim.
        let public_key = parsed.public_key().to_string();
        let fingerprint = parsed.fingerprint(HashAlg::Sha256).to_string();

        Ok(SshKeyView {
            private_key: encoded_key.clone(),
            public_key,
            fingerprint,
            original_private_key: Some(encoded_key),
            is_encrypted: false,
            ssh_key_passphrase: None,
        })
    }
}

/**
 * Decrypt a private key PEM into an unencrypted OpenSSH PEM for agent use.
 * Supports both OpenSSH and PKCS#8 inputs. If already unencrypted OpenSSH, returns it verbatim.
 */
pub fn decrypt_openssh_key(
    encoded_key: String,
    password: String,
) -> Result<String, SshKeyImportError> {
    // Determine the PEM label so we can support OpenSSH and PKCS#8 inputs
    let label = pem_rfc7468::decode_label(encoded_key.as_bytes())
        .map_err(|_| SshKeyImportError::ParsingError)?;

    match label {
        // Encrypted PKCS#8
        pkcs8::EncryptedPrivateKeyInfo::PEM_LABEL => {
            let doc = SecretDocument::from_pkcs8_encrypted_pem(&encoded_key, password.as_bytes())
                .map_err(|err| match err {
                    pkcs8::Error::EncryptedPrivateKey(pkcs5::Error::DecryptFailed) => {
                        SshKeyImportError::WrongPassword
                    }
                    _ => SshKeyImportError::ParsingError,
                })?;

            // Parse DER and convert to OpenSSH
            let private_key_info =
                PrivateKeyInfo::from_der(doc.as_bytes()).map_err(|_| SshKeyImportError::ParsingError)?;

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

            let pem = private_key
                .to_openssh(LineEnding::LF)
                .map_err(|_| SshKeyImportError::ParsingError)?;
            Ok(pem.to_string())
        }
        // Unencrypted PKCS#8: convert directly to OpenSSH
        pkcs8::PrivateKeyInfo::PEM_LABEL => {
            let doc = SecretDocument::from_pkcs8_pem(&encoded_key)
                .map_err(|_| SshKeyImportError::ParsingError)?;

            let private_key_info =
                PrivateKeyInfo::from_der(doc.as_bytes()).map_err(|_| SshKeyImportError::ParsingError)?;

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

            let pem = private_key
                .to_openssh(LineEnding::LF)
                .map_err(|_| SshKeyImportError::ParsingError)?;
            Ok(pem.to_string())
        }
        // OpenSSH input
        ssh_key::PrivateKey::PEM_LABEL => {
            let parsed = ssh_key::private::PrivateKey::from_openssh(&encoded_key).map_err(|err| match err {
                ssh_key::Error::AlgorithmUnknown | ssh_key::Error::AlgorithmUnsupported { .. } => {
                    SshKeyImportError::UnsupportedKeyType
                }
                _ => SshKeyImportError::ParsingError,
            })?;

            if !parsed.is_encrypted() {
                // Already unencrypted, return as-is
                return Ok(encoded_key);
            }

            let decrypted = parsed
                .decrypt(password.as_bytes())
                .map_err(|_| SshKeyImportError::WrongPassword)?;
            let pem = decrypted
                .to_openssh(LineEnding::LF)
                .map_err(|_| SshKeyImportError::ParsingError)?;
            Ok(pem.to_string())
        }
        _ => Err(SshKeyImportError::UnsupportedKeyType),
    }
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

    #[test]
    fn import_key_openssh_encrypted_preserves_input() {
        let original = include_str!("../resources/import/ed25519_openssh_encrypted");
        let result = import_key(original.to_string(), Some("password".to_string())).unwrap();
        assert_eq!(result.private_key, original);
    }

    #[test]
    fn import_key_openssh_unencrypted_preserves_input() {
        let original = include_str!("../resources/import/ed25519_openssh_unencrypted");
        let result = import_key(original.to_string(), Some("".to_string())).unwrap();
        assert_eq!(result.private_key, original);
    }
}
