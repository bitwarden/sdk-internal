//! Parsing and opening an access token (the holder side).

use std::fmt;

use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, CryptoError, EncString, KeyDecryptable, KeyEncryptable, KeySlotIds,
    KeyStoreContext, SymmetricCryptoKey, derive_shareable_key,
};
use bitwarden_encoding::{B64, NotB64EncodedError};
use bitwarden_sensitive_value::SensitiveString;
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AccessTokenError, AccessTokenKind,
    consts::{DERIVE_NAME, TOKEN_VERSION},
};

/// A parsed access token: the holder's recovered OAuth credential and the key derived from the
/// token's seed. The derived key is private and only reaches a [`bitwarden_crypto::KeyStore`]
/// through [`AccessToken::open_payload`], or is used directly to encrypt/decrypt arbitrary data
/// via [`AccessToken::encrypt`] / [`AccessToken::decrypt`], so raw key material never leaves this
/// crate's API.
pub struct AccessToken {
    kind: AccessTokenKind,
    api_key_id: Uuid,
    client_secret: SensitiveString,
    encryption_key: SymmetricCryptoKey,
}

// Redacts the secret and the derived key; only the kind and identifier are safe to log.
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
    /// The token did not split into a `:`-separated prefix and seed, or the prefix's dot-segment
    /// count did not match what the expected [`AccessTokenKind`] requires (four with a
    /// client-kind segment, three without one).
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
    /// Parses a token string against the shape `expected` requires, verifying its client-kind
    /// segment, if `expected` has one, matches.
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

        let seed: B64 = seed_b64.parse()?;
        let seed: Zeroizing<[u8; 16]> =
            Zeroizing::new(seed.as_bytes().try_into().map_err(|_| {
                AccessTokenInvalidError::InvalidLength {
                    expected: 16,
                    got: seed.as_bytes().len(),
                }
            })?);

        Ok(Self {
            kind: expected,
            api_key_id,
            client_secret: SensitiveString::from(client_secret),
            encryption_key: SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
                seed,
                DERIVE_NAME,
                Some(expected.derive_info()),
            )),
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

    /// The OAuth `client_id`: `<kind>.<api_key_id>` when the kind has a wire segment, or the bare
    /// `<api_key_id>` otherwise (Secrets Manager).
    pub fn client_id(&self) -> String {
        match self.kind.segment() {
            Some(segment) => format!("{segment}.{}", self.api_key_id),
            None => self.api_key_id.to_string(),
        }
    }

    /// Parses and decrypts `encrypted_payload` with the key derived from this token's seed,
    /// recovers the organization key, and installs it at `organization_key` in `ctx`.
    ///
    /// The key material never leaves the store, and errors carry no payload content.
    pub fn open_payload<Ids: KeySlotIds>(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        encrypted_payload: &str,
        organization_key: Ids::Symmetric,
    ) -> Result<(), AccessTokenError> {
        let encrypted_payload: EncString = encrypted_payload
            .parse()
            .map_err(|_| AccessTokenError::InvalidPayload)?;

        let decrypted: Vec<u8> = encrypted_payload
            .decrypt_with_key(&self.encryption_key)
            .map_err(|_| AccessTokenError::InvalidPayload)?;

        #[derive(Deserialize)]
        struct Payload {
            #[serde(rename = "encryptionKey")]
            encryption_key: B64,
        }

        let payload: Payload =
            serde_json::from_slice(&decrypted).map_err(|_| AccessTokenError::InvalidPayload)?;

        let key_bytes = BitwardenLegacyKeyBytes::from(&payload.encryption_key);
        let key = SymmetricCryptoKey::try_from(&key_bytes)
            .map_err(|_| AccessTokenError::InvalidOrgKey)?;

        let local = ctx.add_local_symmetric_key(key);
        ctx.persist_symmetric_key(local, organization_key)?;
        Ok(())
    }

    /// The key derived from this token's seed. Crate-private: raw key material must stay behind
    /// this crate's API ([`Self::open_payload`], [`Self::encrypt`], [`Self::decrypt`]).
    pub(crate) fn derived_key(&self) -> &SymmetricCryptoKey {
        &self.encryption_key
    }

    /// Encrypts `plaintext` under this token's derived key. `plaintext` must be valid UTF-8 (the
    /// only encryption path this crate exposes publicly is byte-compatible with, but typed as,
    /// text); callers persisting non-text data should encode it as UTF-8 text (e.g. JSON) first.
    ///
    /// Persistence-neutral: this crate does not know or care what `plaintext` means, or where the
    /// resulting [`EncString`] is stored.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncString, AccessTokenError> {
        let text = std::str::from_utf8(plaintext).map_err(|_| CryptoError::InvalidUtf8String)?;
        Ok(text.encrypt_with_key(self.derived_key())?)
    }

    /// Decrypts `ciphertext` with this token's derived key.
    pub fn decrypt(&self, ciphertext: &EncString) -> Result<Vec<u8>, AccessTokenError> {
        Ok(ciphertext.decrypt_with_key(self.derived_key())?)
    }
}

#[cfg(test)]
impl AccessToken {
    /// Test-only accessor for the derived key's base64, since `encryption_key` is otherwise private
    /// so it never leaves the key store in production code paths.
    pub(crate) fn encryption_key_b64_for_tests(&self) -> String {
        self.encryption_key.to_base64().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Secrets Manager access-token test vector, in the four-part access-token format.
    const VALID_TOKEN: &str = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    /// The same test vector, in Secrets Manager's own three-part format (no client-kind segment).
    const VALID_SM_TOKEN: &str = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    /// Known-answer derived key for [`VALID_SM_TOKEN`], under Secrets Manager's `derive_info`.
    const EXPECTED_KEY_B64: &str =
        "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg==";

    /// Known-answer derived key for [`VALID_TOKEN`], under the access connector's own
    /// `derive_info`. Differs from [`EXPECTED_KEY_B64`] even though both vectors share the same
    /// seed, because the two kinds derive with different HKDF info.
    const EXPECTED_ACCESS_CONNECTOR_KEY_B64: &str =
        "wshEbn7hhFOElbmxzNR4tpotgxjXhowvZH7xSbcpz03yV2cZmNE2/bdkhbzObwt7+mK/oHm+sryfUCXHe1N8pw==";

    fn parse_valid() -> AccessToken {
        AccessToken::parse(VALID_TOKEN, AccessTokenKind::AccessConnector)
            .expect("valid token must parse")
    }

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
        assert_eq!(
            token.encryption_key_b64_for_tests(),
            EXPECTED_ACCESS_CONNECTOR_KEY_B64
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

    /// Same seed, different kind, different key — confirms `derive_info` actually separates the
    /// two kinds' key spaces rather than both collapsing onto the shared `DERIVE_NAME` salt.
    #[test]
    fn access_connector_and_sm_derive_different_keys_from_the_same_seed() {
        let ac_token = AccessToken::parse(VALID_TOKEN, AccessTokenKind::AccessConnector)
            .expect("valid token must parse");
        let sm_token = AccessToken::parse(VALID_SM_TOKEN, AccessTokenKind::SecretsManager)
            .expect("valid token must parse");

        assert_ne!(
            ac_token.encryption_key_b64_for_tests(),
            sm_token.encryption_key_b64_for_tests()
        );
    }

    #[test]
    fn sm_token_matches_the_known_answer() {
        let token = AccessToken::parse(VALID_SM_TOKEN, AccessTokenKind::SecretsManager)
            .expect("valid SM token must parse");
        assert_eq!(token.encryption_key_b64_for_tests(), EXPECTED_KEY_B64);
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

    /// No version segment at all (just `<api-key-id>.<client-secret>`) — one dot-part short of
    /// the three-part SM shape.
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

    fn sm_token() -> AccessToken {
        AccessToken::parse(VALID_SM_TOKEN, AccessTokenKind::SecretsManager)
            .expect("valid SM token must parse")
    }

    /// [`VALID_SM_TOKEN`]'s derived key, computed independently of [`AccessToken`], the way older
    /// SDKs (which encrypted the state file directly under this key) did.
    fn raw_derived_key() -> SymmetricCryptoKey {
        let seed: B64 = "X8vbvA0bduihIDe/qrzIQQ==".parse().unwrap();
        let seed: Zeroizing<[u8; 16]> = Zeroizing::new(seed.as_bytes().try_into().unwrap());
        SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            seed,
            "accesstoken",
            Some("sm-access-token"),
        ))
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let token = sm_token();
        let encrypted = token.encrypt(b"plaintext bytes").expect("encrypt");
        let decrypted = token.decrypt(&encrypted).expect("decrypt");
        assert_eq!(decrypted, b"plaintext bytes");
    }

    /// Data this crate encrypts must stay readable by older SDKs, which decrypt a `String`
    /// directly with the raw derived key (no key store involved).
    #[test]
    fn encrypt_output_decrypts_with_the_raw_derived_key() {
        let token = sm_token();
        let encrypted = token.encrypt(b"a-jwt").expect("encrypt");

        let decrypted: String = encrypted
            .decrypt_with_key(&raw_derived_key())
            .expect("decrypt_with_key");
        assert_eq!(decrypted, "a-jwt");
    }

    /// Data older SDKs wrote (a `String` encrypted directly under the raw derived key) must still
    /// decrypt through this crate's API.
    #[test]
    fn decrypt_reads_data_encrypted_with_the_raw_derived_key() {
        let token = sm_token();
        let encrypted: EncString = "a-jwt"
            .to_string()
            .encrypt_with_key(&raw_derived_key())
            .expect("encrypt_with_key");

        let decrypted = token.decrypt(&encrypted).expect("decrypt");
        assert_eq!(decrypted, b"a-jwt");
    }
}
