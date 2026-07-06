//! Daemon token parsing and key derivation.
//!
//! Operator-provisioned credential string format:
//! `0.daemon.<api-key-id-uuid>.<client-secret>:<b64-16-byte-encryption-key>`
//!
//! The encryption key is derived via [`bitwarden_crypto::derive_shareable_key`] using the
//! constants [`DERIVE_NAME`] and [`DERIVE_INFO`].

use std::{fmt, str::FromStr};

use bitwarden_crypto::{SymmetricCryptoKey, derive_shareable_key};
use bitwarden_encoding::{B64, NotB64EncodedError};
use bitwarden_sensitive_value::SensitiveString;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

/// CONTRACT ITEM C1 — key-derivation name constant.
///
/// Provisionally SM-identical; pinned in e2e (see plan §1, C1).
const DERIVE_NAME: &str = "accesstoken";

/// CONTRACT ITEM C1 — key-derivation info constant.
///
/// Provisionally SM-identical; pinned in e2e (see plan §1, C1).
const DERIVE_INFO: &str = "sm-access-token";

/// Errors that can occur while parsing a [`DaemonToken`] from its string representation.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum DaemonTokenInvalidError {
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

/// A parsed and validated daemon credential token.
///
/// Parsed from the operator-provisioned token string:
/// `0.daemon.<api-key-id-uuid>.<client-secret>:<b64-16-byte-encryption-key>`
pub struct DaemonToken {
    /// The API key identifier used to construct the OAuth `client_id`.
    pub api_key_id: Uuid,
    /// The OAuth client secret. Redacted in [`fmt::Debug`] output.
    pub client_secret: SensitiveString,
    /// The symmetric key derived from the 16-byte seed in the token.
    /// Never logged or exposed in error messages.
    pub encryption_key: SymmetricCryptoKey,
}

// Manual Debug implementation — redacts client_secret and encryption_key.
impl fmt::Debug for DaemonToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonToken")
            .field("api_key_id", &self.api_key_id)
            .finish()
    }
}

impl DaemonToken {
    /// Returns the OAuth `client_id` for this daemon token.
    ///
    /// Format: `daemon.<api_key_id>`.
    pub fn client_id(&self) -> String {
        format!("daemon.{}", self.api_key_id)
    }
}

impl FromStr for DaemonToken {
    type Err = DaemonTokenInvalidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split into the dot-separated prefix and the b64 encryption key.
        let (first_part, encryption_key_b64) = s
            .split_once(':')
            .ok_or(DaemonTokenInvalidError::WrongParts)?;

        // The left half must have exactly 4 dot-separated parts.
        let [version, prefix, api_key_id_str, client_secret_str]: [&str; 4] = first_part
            .split('.')
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| DaemonTokenInvalidError::WrongParts)?;

        if version != "0" {
            return Err(DaemonTokenInvalidError::WrongVersion);
        }

        if prefix != "daemon" {
            return Err(DaemonTokenInvalidError::WrongPrefix);
        }

        let api_key_id: Uuid = api_key_id_str
            .parse()
            .map_err(|_| DaemonTokenInvalidError::InvalidUuid)?;

        // Decode and validate the 16-byte encryption key seed.
        let key_bytes: B64 = encryption_key_b64.parse()?;
        let key_seed: Zeroizing<[u8; 16]> =
            Zeroizing::new(key_bytes.as_bytes().try_into().map_err(|_| {
                DaemonTokenInvalidError::InvalidLength {
                    expected: 16,
                    got: key_bytes.as_bytes().len(),
                }
            })?);

        // Derive the symmetric key from the seed using the C1 constants.
        let derived = derive_shareable_key(key_seed, DERIVE_NAME, Some(DERIVE_INFO));
        let encryption_key = SymmetricCryptoKey::Aes256CbcHmacKey(derived);

        Ok(DaemonToken {
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

    use super::{DaemonToken, DaemonTokenInvalidError};

    /// Token built from the SM test vector's key material, adapted to the 4-part daemon format.
    ///
    /// Original SM vector (access_token.rs): key `X8vbvA0bduihIDe/qrzIQQ==`, uuid
    /// `ec2c1d46-6a4b-4751-a310-af9601317f2d`, secret `C2IgxjjLF7qSshsbwe8JGcbM075YXw`.
    const VALID_TOKEN: &str = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    /// Known-answer derived key for the SM test vector (same C1 constants as access_token.rs).
    const EXPECTED_KEY_B64: &str =
        "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg==";

    #[test]
    fn valid_token_round_trip() {
        let token = DaemonToken::from_str(VALID_TOKEN).expect("valid token must parse");

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

    #[test]
    fn client_id_format() {
        let token = DaemonToken::from_str(VALID_TOKEN).expect("valid token must parse");
        assert_eq!(
            token.client_id(),
            "daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d"
        );
    }

    #[test]
    fn base64_without_padding_is_accepted() {
        // The SM test shows padding-free b64 is accepted.
        let t = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ";
        assert!(DaemonToken::from_str(t).is_ok());
    }

    #[test]
    fn wrong_version_is_rejected() {
        let t = "1.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            DaemonToken::from_str(t),
            Err(DaemonTokenInvalidError::WrongVersion)
        ));
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let t = "0.access.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            DaemonToken::from_str(t),
            Err(DaemonTokenInvalidError::WrongPrefix)
        ));
    }

    #[test]
    fn missing_colon_gives_wrong_parts() {
        // SM format (3 dot-parts) — missing the colon/key entirely.
        let t = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw.X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            DaemonToken::from_str(t),
            Err(DaemonTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn too_few_dot_parts_gives_wrong_parts() {
        // Only 3 dot-parts before the colon (SM format).
        let t = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            DaemonToken::from_str(t),
            Err(DaemonTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn too_many_dot_parts_gives_wrong_parts() {
        let t = "0.daemon.extra.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            DaemonToken::from_str(t),
            Err(DaemonTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn invalid_uuid_is_rejected() {
        let t = "0.daemon.not-a-uuid.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            DaemonToken::from_str(t),
            Err(DaemonTokenInvalidError::InvalidUuid)
        ));
    }

    #[test]
    fn invalid_base64_is_rejected() {
        // '!' is not a valid base64 character.
        let t = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:!!!notbase64!!!";
        assert!(matches!(
            DaemonToken::from_str(t),
            Err(DaemonTokenInvalidError::InvalidBase64(_))
        ));
    }

    #[test]
    fn wrong_key_length_is_rejected() {
        // 15-byte key (too short).
        use bitwarden_encoding::B64;
        let short_key = B64::from([0u8; 15].as_slice()).to_string();
        let t = format!("0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:{short_key}");
        assert!(matches!(
            DaemonToken::from_str(&t),
            Err(DaemonTokenInvalidError::InvalidLength {
                expected: 16,
                got: 15
            })
        ));
    }

    #[test]
    fn debug_output_contains_no_secret_material() {
        let token = DaemonToken::from_str(VALID_TOKEN).expect("valid token must parse");
        let debug_str = format!("{token:?}");

        // Must not contain the client secret.
        assert!(
            !debug_str.contains("C2IgxjjLF7qSshsbwe8JGcbM075YXw"),
            "debug output leaked client_secret: {debug_str}"
        );
        // Must not contain key material.
        assert!(
            !debug_str.contains("X8vbvA0bduihIDe"),
            "debug output leaked key bytes: {debug_str}"
        );
        // Should identify the struct and include the non-sensitive api_key_id.
        assert!(debug_str.contains("DaemonToken"));
        assert!(debug_str.contains("ec2c1d46-6a4b-4751-a310-af9601317f2d"));
    }
}
