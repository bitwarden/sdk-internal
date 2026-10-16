//! Parsing and opening an access token (the holder side).

use std::fmt;

use bitwarden_access_token_crypto::{AccessTokenError, AccessTokenKey, AccessTokenSeed};
use bitwarden_crypto::{KeySlotIds, KeyStoreContext};
use bitwarden_encoding::{B64, NotB64EncodedError};
use bitwarden_sensitive_value::SensitiveString;
use thiserror::Error;
use uuid::Uuid;

use crate::{AccessTokenKind, consts::TOKEN_VERSION};

/// A parsed access token. The derived key only reaches a key store through
/// [`Self::open_payload`].
pub struct AccessToken {
    kind: AccessTokenKind,
    api_key_id: Uuid,
    client_secret: SensitiveString,
    key: AccessTokenKey,
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("kind", &self.kind)
            .field("api_key_id", &self.api_key_id)
            .finish_non_exhaustive()
    }
}

/// Reasons an access token string could not be parsed.
///
/// Not `PartialEq`: the base64 variant wraps [`NotB64EncodedError`], which does not implement it.
#[derive(Debug, Error)]
pub enum AccessTokenInvalidError {
    /// Missing `:`, or the wrong number of dot-segments for the expected [`AccessTokenKind`].
    #[error("Has the wrong number of parts")]
    WrongParts,
    /// The version segment was not `0`.
    #[error("Is the wrong version")]
    WrongVersion,
    /// The client-kind segment did not match the expected [`AccessTokenKind`].
    #[error("Has the wrong prefix")]
    WrongPrefix,
    /// The API key id segment was not a UUID.
    #[error("Has an invalid identifier")]
    InvalidUuid,
    /// The seed was not valid base64.
    #[error("Error decoding base64: {0}")]
    InvalidBase64(#[from] NotB64EncodedError),
    /// The seed decoded to something other than 16 bytes.
    #[error("Invalid base64 length: expected {expected}, got {got}")]
    InvalidLength {
        /// The length the format requires.
        expected: usize,
        /// The decoded length.
        got: usize,
    },
}

impl AccessToken {
    /// Parses a token in the shape `expected` requires, including its client-kind segment.
    pub fn parse(token: &str, expected: AccessTokenKind) -> Result<Self, AccessTokenInvalidError> {
        let (prefix, seed_b64) = token
            .split_once(':')
            .ok_or(AccessTokenInvalidError::WrongParts)?;

        let parts: Vec<&str> = prefix.split('.').collect();

        let (version, client_kind, api_key_id, client_secret): (&str, Option<&str>, &str, &str) =
            match expected.segment() {
                Some(_) => {
                    let [version, client_kind, api_key_id, client_secret]: [&str; 4] = parts
                        .try_into()
                        .map_err(|_| AccessTokenInvalidError::WrongParts)?;
                    (version, Some(client_kind), api_key_id, client_secret)
                }
                None => {
                    let [version, api_key_id, client_secret]: [&str; 3] = parts
                        .try_into()
                        .map_err(|_| AccessTokenInvalidError::WrongParts)?;
                    (version, None, api_key_id, client_secret)
                }
            };

        if version != TOKEN_VERSION {
            return Err(AccessTokenInvalidError::WrongVersion);
        }

        if client_kind != expected.segment() {
            return Err(AccessTokenInvalidError::WrongPrefix);
        }

        let api_key_id = api_key_id
            .parse()
            .map_err(|_| AccessTokenInvalidError::InvalidUuid)?;

        let seed_b64: B64 = seed_b64.parse()?;
        let seed = AccessTokenSeed::try_from(seed_b64.as_bytes()).map_err(|e| {
            AccessTokenInvalidError::InvalidLength {
                expected: e.expected,
                got: e.got,
            }
        })?;

        Ok(Self {
            kind: expected,
            api_key_id,
            client_secret: SensitiveString::from(client_secret),
            key: AccessTokenKey::derive(&seed, expected.key_purpose()),
        })
    }

    /// The API key identifier. See [`Self::client_id`] for the full OAuth `client_id`.
    pub fn api_key_id(&self) -> Uuid {
        self.api_key_id
    }

    /// The OAuth client secret.
    pub fn client_secret(&self) -> &SensitiveString {
        &self.client_secret
    }

    /// Which [`AccessTokenKind`] this token authenticates.
    pub fn kind(&self) -> AccessTokenKind {
        self.kind
    }

    /// The OAuth `client_id`: `<kind>.<api_key_id>`, or the bare `<api_key_id>` for Secrets
    /// Manager.
    pub fn client_id(&self) -> String {
        match self.kind.segment() {
            Some(segment) => format!("{segment}.{}", self.api_key_id),
            None => self.api_key_id.to_string(),
        }
    }

    /// Decrypts `encrypted_payload` and installs the organization key it carries at
    /// `organization_key` in `ctx`. Errors carry no payload content.
    pub fn open_payload<Ids: KeySlotIds>(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        encrypted_payload: &str,
        organization_key: Ids::Symmetric,
    ) -> Result<(), AccessTokenError> {
        self.key
            .open_payload(ctx, encrypted_payload, organization_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Secrets Manager test vector, in the four-part format.
    const VALID_TOKEN: &str = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    /// The same vector in Secrets Manager's three-part format.
    const VALID_SM_TOKEN: &str = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    fn parse_valid() -> AccessToken {
        AccessToken::parse(VALID_TOKEN, AccessTokenKind::AccessConnector)
            .expect("valid token must parse")
    }

    /// Derived-key bytes are covered by `bitwarden-access-token-crypto`'s known-answer tests.
    #[test]
    fn valid_token_round_trip() {
        let token = parse_valid();

        assert_eq!(
            token.api_key_id().to_string(),
            "ec2c1d46-6a4b-4751-a310-af9601317f2d"
        );
        use bitwarden_sensitive_value::ExposeSensitive as _;
        assert_eq!(
            token.client_secret().expose(),
            "C2IgxjjLF7qSshsbwe8JGcbM075YXw"
        );
    }

    #[test]
    fn client_id_format() {
        let token = parse_valid();
        assert_eq!(
            token.client_id(),
            "access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d"
        );
    }

    #[test]
    fn base64_without_padding_is_accepted() {
        let t = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ";
        assert!(AccessToken::parse(t, AccessTokenKind::AccessConnector).is_ok());
    }

    #[test]
    fn wrong_version_is_rejected() {
        let t = "1.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessToken::parse(t, AccessTokenKind::AccessConnector),
            Err(AccessTokenInvalidError::WrongVersion)
        ));
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let t = "0.access.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessToken::parse(t, AccessTokenKind::AccessConnector),
            Err(AccessTokenInvalidError::WrongPrefix)
        ));
    }

    #[test]
    fn missing_colon_gives_wrong_parts() {
        // The key follows a dot instead of the colon.
        let t = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw.X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessToken::parse(t, AccessTokenKind::AccessConnector),
            Err(AccessTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn too_few_dot_parts_gives_wrong_parts() {
        let t = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessToken::parse(t, AccessTokenKind::AccessConnector),
            Err(AccessTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn too_many_dot_parts_gives_wrong_parts() {
        let t = "0.access-connector.extra.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessToken::parse(t, AccessTokenKind::AccessConnector),
            Err(AccessTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn invalid_uuid_is_rejected() {
        let t =
            "0.access-connector.not-a-uuid.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessToken::parse(t, AccessTokenKind::AccessConnector),
            Err(AccessTokenInvalidError::InvalidUuid)
        ));
    }

    #[test]
    fn invalid_base64_is_rejected() {
        let t = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:!!!notbase64!!!";
        assert!(matches!(
            AccessToken::parse(t, AccessTokenKind::AccessConnector),
            Err(AccessTokenInvalidError::InvalidBase64(_))
        ));
    }

    #[test]
    fn wrong_key_length_is_rejected() {
        let short_key = B64::from([0u8; 15].as_slice()).to_string();
        let t =
            format!("0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:{short_key}");
        assert!(matches!(
            AccessToken::parse(&t, AccessTokenKind::AccessConnector),
            Err(AccessTokenInvalidError::InvalidLength {
                expected: 16,
                got: 15
            })
        ));
    }

    #[test]
    fn sm_token_matches_the_known_answer() {
        let token = AccessToken::parse(VALID_SM_TOKEN, AccessTokenKind::SecretsManager)
            .expect("valid SM token must parse");
        assert_eq!(token.client_id(), "ec2c1d46-6a4b-4751-a310-af9601317f2d");
        use bitwarden_sensitive_value::ExposeSensitive as _;
        assert_eq!(
            token.client_secret().expose(),
            "C2IgxjjLF7qSshsbwe8JGcbM075YXw"
        );
    }

    #[test]
    fn sm_base64_without_padding_is_accepted() {
        let t = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ";
        assert!(AccessToken::parse(t, AccessTokenKind::SecretsManager).is_ok());
    }

    #[test]
    fn sm_wrong_version_is_rejected() {
        let t = "1.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessToken::parse(t, AccessTokenKind::SecretsManager),
            Err(AccessTokenInvalidError::WrongVersion)
        ));
    }

    /// No version segment: one part short of the Secrets Manager shape.
    #[test]
    fn sm_missing_version_segment_is_wrong_parts() {
        let t = "ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";
        assert!(matches!(
            AccessToken::parse(t, AccessTokenKind::SecretsManager),
            Err(AccessTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn access_connector_token_parsed_as_sm_is_wrong_parts() {
        assert!(matches!(
            AccessToken::parse(VALID_TOKEN, AccessTokenKind::SecretsManager),
            Err(AccessTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn sm_token_parsed_as_access_connector_is_wrong_parts() {
        assert!(matches!(
            AccessToken::parse(VALID_SM_TOKEN, AccessTokenKind::AccessConnector),
            Err(AccessTokenInvalidError::WrongParts)
        ));
    }

    #[test]
    fn debug_output_contains_no_secret_material() {
        let token = parse_valid();
        let debug_str = format!("{token:?}");

        assert!(
            !debug_str.contains("C2IgxjjLF7qSshsbwe8JGcbM075YXw"),
            "debug output leaked client_secret: {debug_str}"
        );
        assert!(
            !debug_str.contains("X8vbvA0bduihIDe"),
            "debug output leaked key bytes: {debug_str}"
        );
        assert!(debug_str.contains("AccessToken"));
        assert!(debug_str.contains("ec2c1d46-6a4b-4751-a310-af9601317f2d"));
    }
}
