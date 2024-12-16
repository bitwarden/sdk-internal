use ed25519;
use pkcs8::{
    der::Decode, EncryptedPrivateKeyInfo, ObjectIdentifier, PrivateKeyInfo, SecretDocument,
};
use serde::{Deserialize, Serialize};
use ssh_key::{
    private::{Ed25519Keypair, RsaKeypair},
    HashAlg, LineEnding,
};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

use crate::{error::SshKeyImportError, SshKey};

const PKCS1_HEADER: &str = "-----BEGIN RSA PRIVATE KEY-----";
const PKCS8_UNENCRYPTED_HEADER: &str = "-----BEGIN PRIVATE KEY-----";
const PKCS8_ENCRYPTED_HEADER: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const OPENSSH_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";

pub const RSA_PKCS8_ALGORITHM_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
enum KeyType {
    Ed25519,
    Rsa,
    Unknown,
}

pub fn import_key(encoded_key: String, password: String) -> Result<SshKey, SshKeyImportError> {
    match encoded_key.lines().next() {
        Some(PKCS1_HEADER) => Err(SshKeyImportError::UnsupportedKeyType),
        Some(PKCS8_UNENCRYPTED_HEADER) => {
            import_pkcs8_key(encoded_key, None).map_err(|_| SshKeyImportError::ParsingError)
        }
        Some(PKCS8_ENCRYPTED_HEADER) => import_pkcs8_key(encoded_key, Some(password)),
        Some(OPENSSH_HEADER) => import_openssh_key(encoded_key, password),
        _ => Err(SshKeyImportError::ParsingError),
    }
}

fn import_pkcs8_key(
    encoded_key: String,
    password: Option<String>,
) -> Result<SshKey, SshKeyImportError> {
    let der = match SecretDocument::from_pem(&encoded_key) {
        Ok((_, doc)) => doc,
        Err(_) => return Err(SshKeyImportError::ParsingError),
    };

    let decrypted_der = match password.clone() {
        Some(password) => {
            let encrypted_private_key_info = EncryptedPrivateKeyInfo::from_der(der.as_bytes())
                .map_err(|_| SshKeyImportError::ParsingError)?;
            encrypted_private_key_info
                .decrypt(password.as_bytes())
                .map_err(|_| SshKeyImportError::WrongPassword)?
        }
        None => der,
    };

    let key_type: KeyType = match PrivateKeyInfo::from_der(decrypted_der.as_bytes())
        .map_err(|_| SshKeyImportError::ParsingError)?
        .algorithm
        .oid
    {
        ed25519::pkcs8::ALGORITHM_OID => KeyType::Ed25519,
        RSA_PKCS8_ALGORITHM_OID => KeyType::Rsa,
        _ => KeyType::Unknown,
    };

    match key_type {
        KeyType::Ed25519 => {
            let private_key: ed25519::KeypairBytes = match password {
                Some(password) => {
                    pkcs8::DecodePrivateKey::from_pkcs8_encrypted_pem(&encoded_key, password)
                        .map_err(|err| match err {
                            ed25519::pkcs8::Error::EncryptedPrivateKey(_) => {
                                SshKeyImportError::WrongPassword
                            }
                            _ => SshKeyImportError::ParsingError,
                        })?
                }
                None => ed25519::pkcs8::DecodePrivateKey::from_pkcs8_pem(&encoded_key)
                    .map_err(|_| SshKeyImportError::ParsingError)?,
            };
            let private_key = ssh_key::private::PrivateKey::from(Ed25519Keypair::from(
                &private_key.secret_key.into(),
            ));
            Ok(SshKey {
                private_key: private_key.to_openssh(LineEnding::LF).unwrap().to_string(),
                public_key: private_key.public_key().to_string(),
                key_fingerprint: private_key.fingerprint(HashAlg::Sha256).to_string(),
            })
        }
        KeyType::Rsa => {
            let private_key: rsa::RsaPrivateKey = match password {
                Some(password) => {
                    pkcs8::DecodePrivateKey::from_pkcs8_encrypted_pem(&encoded_key, password)
                        .map_err(|err| match err {
                            pkcs8::Error::EncryptedPrivateKey(_) => {
                                SshKeyImportError::WrongPassword
                            }
                            _ => SshKeyImportError::ParsingError,
                        })?
                }
                None => pkcs8::DecodePrivateKey::from_pkcs8_pem(&encoded_key)
                    .map_err(|_| SshKeyImportError::ParsingError)?,
            };

            let private_key = ssh_key::private::PrivateKey::from(
                RsaKeypair::try_from(private_key).map_err(|_| SshKeyImportError::ParsingError)?,
            );
            let private_key_openssh = private_key
                .to_openssh(LineEnding::LF)
                .map_err(|_| SshKeyImportError::ParsingError)?;
            Ok(SshKey {
                private_key: private_key_openssh.to_string(),
                public_key: private_key.public_key().to_string(),
                key_fingerprint: private_key.fingerprint(HashAlg::Sha256).to_string(),
            })
        }
        _ => Err(SshKeyImportError::UnsupportedKeyType),
    }
}

fn import_openssh_key(encoded_key: String, password: String) -> Result<SshKey, SshKeyImportError> {
    let private_key = match ssh_key::private::PrivateKey::from_openssh(&encoded_key) {
        Ok(k) => k,
        Err(err) => match err {
            ssh_key::Error::AlgorithmUnknown
            | ssh_key::Error::AlgorithmUnsupported { algorithm: _ } => {
                return Err(SshKeyImportError::UnsupportedKeyType)
            }
            _ => return Err(SshKeyImportError::ParsingError),
        },
    };

    if private_key.is_encrypted() && password.is_empty() {
        return Err(SshKeyImportError::PasswordRequired);
    }
    let private_key = if private_key.is_encrypted() {
        private_key
            .decrypt(password.as_bytes())
            .map_err(|_| SshKeyImportError::WrongPassword)?
    } else {
        private_key
    };
    let private_key_openssh = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|_| SshKeyImportError::ParsingError)?;

    Ok(SshKey {
        private_key: private_key_openssh.to_string(),
        public_key: private_key.public_key().to_string(),
        key_fingerprint: private_key.fingerprint(HashAlg::Sha256).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_key_ed25519_openssh_unencrypted() {
        let private_key = include_str!("../resources/ed25519_openssh_unencrypted");
        let public_key = include_str!("../resources/ed25519_openssh_unencrypted.pub").trim();
        let result = import_key(private_key.to_string(), "".to_string()).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_ed25519_openssh_encrypted() {
        let private_key = include_str!("../resources/ed25519_openssh_encrypted");
        let public_key = include_str!("../resources/ed25519_openssh_encrypted.pub").trim();
        let result = import_key(private_key.to_string(), "password".to_string()).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_openssh_unencrypted() {
        let private_key = include_str!("../resources/rsa_openssh_unencrypted");
        let public_key = include_str!("../resources/rsa_openssh_unencrypted.pub").trim();
        let result = import_key(private_key.to_string(), "".to_string()).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_openssh_encrypted() {
        let private_key = include_str!("../resources/rsa_openssh_encrypted");
        let public_key = include_str!("../resources/rsa_openssh_encrypted.pub").trim();
        let result = import_key(private_key.to_string(), "password".to_string()).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_ed25519_pkcs8_unencrypted() {
        let private_key = include_str!("../resources/ed25519_pkcs8_unencrypted");
        let public_key =
            include_str!("../resources/ed25519_pkcs8_unencrypted.pub").replace("testkey", "");
        let public_key = public_key.trim();
        let result = import_key(private_key.to_string(), "".to_string()).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_pkcs8_unencrypted() {
        let private_key = include_str!("../resources/rsa_pkcs8_unencrypted");
        // for whatever reason pkcs8 + rsa does not include the comment in the public key
        let public_key =
            include_str!("../resources/rsa_pkcs8_unencrypted.pub").replace("testkey", "");
        let public_key = public_key.trim();
        let result = import_key(private_key.to_string(), "".to_string()).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_rsa_pkcs8_encrypted() {
        let private_key = include_str!("../resources/rsa_pkcs8_encrypted");
        let public_key =
            include_str!("../resources/rsa_pkcs8_encrypted.pub").replace("testkey", "");
        let public_key = public_key.trim();
        let result = import_key(private_key.to_string(), "password".to_string()).unwrap();
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn import_key_ed25519_openssh_encrypted_wrong_password() {
        let private_key = include_str!("../resources/ed25519_openssh_encrypted");
        let result = import_key(private_key.to_string(), "wrongpassword".to_string());
        assert_eq!(result.unwrap_err(), SshKeyImportError::WrongPassword);
    }

    #[test]
    fn import_non_key_error() {
        let result = import_key("not a key".to_string(), "".to_string());
        assert_eq!(result.unwrap_err(), SshKeyImportError::ParsingError);
    }

    #[test]
    fn import_ecdsa_error() {
        let private_key = include_str!("../resources/ecdsa_openssh_unencrypted");
        let result = import_key(private_key.to_string(), "".to_string());
        assert_eq!(result.unwrap_err(), SshKeyImportError::UnsupportedKeyType);
    }

    // Putty-exported keys should be supported, but are not due to a parser incompatibility.
    // Should this test start failing, please change it to expect a correct key, and
    // make sure the documentation support for putty-exported keys this is updated.
    // https://bitwarden.atlassian.net/browse/PM-14989
    #[test]
    fn import_key_ed25519_putty() {
        let private_key = include_str!("../resources/ed25519_putty_openssh_unencrypted");
        let result = import_key(private_key.to_string(), "".to_string());
        assert_eq!(result.unwrap_err(), SshKeyImportError::ParsingError);
    }

    // Putty-exported keys should be supported, but are not due to a parser incompatibility.
    // Should this test start failing, please change it to expect a correct key, and
    // make sure the documentation support for putty-exported keys this is updated.
    // https://bitwarden.atlassian.net/browse/PM-14989
    #[test]
    fn import_key_rsa_openssh_putty() {
        let private_key = include_str!("../resources/rsa_putty_openssh_unencrypted");
        let result = import_key(private_key.to_string(), "".to_string());
        assert_eq!(result.unwrap_err(), SshKeyImportError::ParsingError);
    }

    #[test]
    fn import_key_rsa_pkcs8_putty() {
        let private_key = include_str!("../resources/rsa_putty_pkcs1_unencrypted");
        let result = import_key(private_key.to_string(), "".to_string());
        assert_eq!(result.unwrap_err(), SshKeyImportError::UnsupportedKeyType);
    }
}
