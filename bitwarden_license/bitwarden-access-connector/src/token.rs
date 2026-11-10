//! Access connector token parsing and key derivation.

use std::{fmt, str::FromStr};

use bitwarden_crypto::{SymmetricCryptoKey, derive_shareable_key};
use bitwarden_encoding::{B64, NotB64EncodedError};
use bitwarden_sensitive_value::SensitiveString;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The token's client-kind segment and the OAuth `client_id` prefix. It must match
/// `TOKEN_CLIENT_KIND` in `bitwarden-pam`, which issues the token, and the server's
/// `PamAccessConnectorClientProvider.AccessConnectorPrefix`.
pub const TOKEN_CLIENT_KIND: &str = "access-connector";

/// Key-derivation name, shared with Secrets Manager. It must match `bitwarden-pam`'s registration;
/// public so `examples/register.rs` derives the same key.
pub const DERIVE_NAME: &str = "accesstoken";

/// Key-derivation info, shared with Secrets Manager. It must match `bitwarden-pam`'s registration;
/// public so `examples/register.rs` derives the same key.
pub const DERIVE_INFO: &str = "sm-access-token";

/// Errors from parsing an [`AccessConnectorToken`].
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum AccessConnectorTokenInvalidError {
    #[error("Has the wrong number of parts")]
    WrongParts,
    #[error("Is the wrong version")]
    WrongVersion,
    #[error("Has the wrong prefix")]
    WrongPrefix,
    #[error("Has an invalid identifier")]
    InvalidUuid,
    #[error("Error decoding base64: {0}")]
    InvalidBase64(#[from] NotB64EncodedError),
    #[error("Invalid base64 length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

/// A parsed access connector token, from the operator-provisioned string
/// `0.access-connector.<api-key-id-uuid>.<client-secret>:<b64-16-byte-encryption-key>`.
pub struct AccessConnectorToken {
    /// The API key identifier used to construct the OAuth `client_id`.
    pub api_key_id: Uuid,
    /// The OAuth client secret. Redacted in [`fmt::Debug`] output.
    pub client_secret: SensitiveString,
    /// The symmetric key derived from the 16-byte seed in the token.
    /// Never logged or exposed in error messages.
    pub encryption_key: SymmetricCryptoKey,
}

// Hand-written to leave out client_secret and encryption_key.
impl fmt::Debug for AccessConnectorToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessConnectorToken")
            .field("api_key_id", &self.api_key_id)
            .finish()
    }
}

impl AccessConnectorToken {
    /// The OAuth `client_id`: `<TOKEN_CLIENT_KIND>.<api_key_id>`.
    pub fn client_id(&self) -> String {
        format!("{TOKEN_CLIENT_KIND}.{}", self.api_key_id)
    }
}

impl FromStr for AccessConnectorToken {
    type Err = AccessConnectorTokenInvalidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (first_part, encryption_key_b64) = s
            .split_once(':')
            .ok_or(AccessConnectorTokenInvalidError::WrongParts)?;

        let [version, prefix, api_key_id_str, client_secret_str]: [&str; 4] = first_part
            .split('.')
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| AccessConnectorTokenInvalidError::WrongParts)?;

        if version != "0" {
            return Err(AccessConnectorTokenInvalidError::WrongVersion);
        }

        if prefix != TOKEN_CLIENT_KIND {
            return Err(AccessConnectorTokenInvalidError::WrongPrefix);
        }

        let api_key_id: Uuid = api_key_id_str
            .parse()
            .map_err(|_| AccessConnectorTokenInvalidError::InvalidUuid)?;

        let key_bytes: B64 = encryption_key_b64.parse()?;
        let key_seed: Zeroizing<[u8; 16]> =
            Zeroizing::new(key_bytes.as_bytes().try_into().map_err(|_| {
                AccessConnectorTokenInvalidError::InvalidLength {
                    expected: 16,
                    got: key_bytes.as_bytes().len(),
                }
            })?);

        let derived = derive_shareable_key(key_seed, DERIVE_NAME, Some(DERIVE_INFO));
        let encryption_key = SymmetricCryptoKey::Aes256CbcHmacKey(derived);

        Ok(AccessConnectorToken {
            api_key_id,
            client_secret: SensitiveString::from(client_secret_str),
            encryption_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitwarden_sensitive_value::ExposeSensitive;

    use super::{AccessConnectorToken, AccessConnectorTokenInvalidError, TOKEN_CLIENT_KIND};

    /// The Secrets Manager access-token test vector, in the connector's 4-part format.
    const VALID_TOKEN: &str = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    /// Known-answer derived key for that vector.
    const EXPECTED_KEY_B64: &str =
        "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg==";

    #[test]
    fn valid_token_round_trip() {
        let token = AccessConnectorToken::from_str(VALID_TOKEN).expect("valid token must parse");

        assert_eq!(
            token.api_key_id.to_string(),
            "ec2c1d46-6a4b-4751-a310-af9601317f2d"
        );
        assert_eq!(
            token.client_secret.expose(),
            "C2IgxjjLF7qSshsbwe8JGcbM075YXw"
        );
        assert_eq!(
            token.encryption_key.to_base64().to_string(),
            EXPECTED_KEY_B64
        );
    }

    /// If this fails, check `bitwarden-pam`'s `TOKEN_CLIENT_KIND` and the server's
    /// `PamAccessConnectorClientProvider.AccessConnectorPrefix` before changing it, since a
    /// mismatch yields tokens that parse but cannot authenticate.
    #[test]
    fn client_kind_matches_the_issuer_and_the_server() {
        assert_eq!(TOKEN_CLIENT_KIND, "access-connector");

        let token = AccessConnectorToken::from_str(VALID_TOKEN).expect("valid token must parse");
        assert!(
            token
                .client_id()
                .starts_with(&format!("{TOKEN_CLIENT_KIND}.")),
            "client_id must be built from the same constant the parser accepts: {}",
            token.client_id()
        );
    }

    #[test]
    fn client_id_format() {
        let token = AccessConnectorToken::from_str(VALID_TOKEN).expect("valid token must parse");
        assert_eq!(
            token.client_id(),
            "access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d"
        );
    }

    #[test]
    fn base64_without_padding_is_accepted() {
        let t = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ";
        assert!(AccessConnectorToken::from_str(t).is_ok());
    }

    #[test]
    fn wrong_version_is_rejected() {
        let t = "1.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessConnectorToken::from_str(t),
            Err(AccessConnectorTokenInvalidError::WrongVersion)
        ));
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let t = "0.access.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessConnectorToken::from_str(t),
            Err(AccessConnectorTokenInvalidError::WrongPrefix)
        ));
    }

    #[test]
    fn missing_colon_gives_wrong_parts() {
        // The key follows a dot instead of the colon.
        let t = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw.X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessConnectorToken::from_str(t),
            Err(AccessConnectorTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn too_few_dot_parts_gives_wrong_parts() {
        let t = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessConnectorToken::from_str(t),
            Err(AccessConnectorTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn too_many_dot_parts_gives_wrong_parts() {
        let t = "0.access-connector.extra.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessConnectorToken::from_str(t),
            Err(AccessConnectorTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn invalid_uuid_is_rejected() {
        let t =
            "0.access-connector.not-a-uuid.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessConnectorToken::from_str(t),
            Err(AccessConnectorTokenInvalidError::InvalidUuid)
        ));
    }

    #[test]
    fn invalid_base64_is_rejected() {
        let t = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:!!!notbase64!!!";
        assert!(matches!(
            AccessConnectorToken::from_str(t),
            Err(AccessConnectorTokenInvalidError::InvalidBase64(_))
        ));
    }

    #[test]
    fn wrong_key_length_is_rejected() {
        use bitwarden_encoding::B64;
        let short_key = B64::from([0u8; 15].as_slice()).to_string();
        let t =
            format!("0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:{short_key}");
        assert!(matches!(
            AccessConnectorToken::from_str(&t),
            Err(AccessConnectorTokenInvalidError::InvalidLength {
                expected: 16,
                got: 15
            })
        ));
    }

    #[test]
    fn debug_output_contains_no_secret_material() {
        let token = AccessConnectorToken::from_str(VALID_TOKEN).expect("valid token must parse");
        let debug_str = format!("{token:?}");

        assert!(
            !debug_str.contains("C2IgxjjLF7qSshsbwe8JGcbM075YXw"),
            "debug output leaked client_secret: {debug_str}"
        );
        assert!(
            !debug_str.contains("X8vbvA0bduihIDe"),
            "debug output leaked key bytes: {debug_str}"
        );
        assert!(debug_str.contains("AccessConnectorToken"));
        assert!(debug_str.contains("ec2c1d46-6a4b-4751-a310-af9601317f2d"));
    }
}
