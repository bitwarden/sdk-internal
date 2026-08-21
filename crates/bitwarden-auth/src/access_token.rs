use std::{fmt::Debug, str::FromStr};

use bitwarden_crypto::{SymmetricCryptoKey, derive_shareable_key};
use bitwarden_encoding::{B64, NotB64EncodedError};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum AccessTokenInvalidError {
    #[error("Doesn't contain a decryption key")]
    NoKey,
    #[error("Has the wrong number of parts")]
    WrongParts,
    #[error("Is the wrong version")]
    WrongVersion,
    #[error("Has an invalid identifier")]
    InvalidUuid,

    #[error("Error decoding base64: {0}")]
    InvalidBase64(#[from] NotB64EncodedError),

    #[error("Invalid base64 length: expected {expected}, got {got}")]
    InvalidBase64Length { expected: usize, got: usize },
}

/// Access Token
pub struct AccessToken {
    /// The ID of the access token
    pub access_token_id: Uuid,
    /// The client secret
    pub client_secret: String,
    /// The encryption key used to decrypt a payload to retrieve the organization key.
    pub encryption_key: SymmetricCryptoKey,
}

// We don't want to log the more sensitive fields from an AccessToken
impl Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("access_token_id", &self.access_token_id)
            .finish()
    }
}

impl FromStr for AccessToken {
    type Err = AccessTokenInvalidError;

    fn from_str(key: &str) -> std::result::Result<Self, Self::Err> {
        let (first_part, encryption_key) =
            key.split_once(':').ok_or(AccessTokenInvalidError::NoKey)?;

        let [version, access_token_id, client_secret]: [&str; 3] = first_part
            .split('.')
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| AccessTokenInvalidError::WrongParts)?;

        if version != "0" {
            return Err(AccessTokenInvalidError::WrongVersion);
        }

        let Ok(access_token_id) = access_token_id.parse() else {
            return Err(AccessTokenInvalidError::InvalidUuid);
        };

        let encryption_key: B64 = encryption_key.parse()?;
        let encryption_key =
            Zeroizing::new(encryption_key.as_bytes().try_into().map_err(|_| {
                AccessTokenInvalidError::InvalidBase64Length {
                    expected: 16,
                    got: encryption_key.as_bytes().len(),
                }
            })?);
        let encryption_key =
            derive_shareable_key(encryption_key, "accesstoken", Some("sm-access-token"));

        Ok(AccessToken {
            access_token_id,
            client_secret: client_secret.to_owned(),
            encryption_key: SymmetricCryptoKey::Aes256CbcHmacKey(encryption_key),
        })
    }
}

#[cfg(test)]
mod tests {

    use super::AccessToken;

    #[test]
    fn can_decode_access_token() {
        use std::str::FromStr;

        let access_token = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        let token = AccessToken::from_str(access_token).unwrap();

        assert_eq!(
            &token.access_token_id.to_string(),
            "ec2c1d46-6a4b-4751-a310-af9601317f2d"
        );
        assert_eq!(token.client_secret, "C2IgxjjLF7qSshsbwe8JGcbM075YXw");
        assert_eq!(
            token.encryption_key.to_base64().to_string(),
            "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg=="
        );
    }

    #[test]
    fn malformed_tokens() {
        use std::str::FromStr;

        // Encryption key without base64 padding, we generate it with padding but ignore it when
        // decoding
        let t = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ";
        assert!(AccessToken::from_str(t).is_ok());

        // Invalid version
        let t = "1.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(AccessToken::from_str(t).is_err());

        // Invalid splits
        let t = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw.X8vbvA0bduihIDe/qrzIQQ==";
        assert!(AccessToken::from_str(t).is_err());

        let t = "ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(AccessToken::from_str(t).is_err());

        // Invalid base64
        let t = "1.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe9qrzIQQ==";
        assert!(AccessToken::from_str(t).is_err());
    }
}
