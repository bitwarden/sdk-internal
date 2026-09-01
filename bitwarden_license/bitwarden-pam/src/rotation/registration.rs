//! The cryptographic half of registering an access connector.
//!
//! A connector runs unattended, outside any user's session, so it cannot unlock a vault the way a
//! client does. Registration therefore hands it the organization key up front, wrapped so that only
//! the holder of one operator-provisioned token can unwrap it:
//!
//! 1. A fresh 16-byte seed is generated. Base64-encoded, it becomes the `:` suffix of the token.
//! 2. A symmetric key is derived from that seed via
//!    [`derive_shareable_key`](bitwarden_crypto::derive_shareable_key), using [`DERIVE_NAME`] and
//!    [`DERIVE_INFO`].
//! 3. `encryptedPayload` - `{"encryptionKey":"<org key b64>"}` - is encrypted under the derived
//!    key. The connector re-derives that key from the seed in its token and unwraps the
//!    organization key.
//! 4. `key` is the derived key's base64, encrypted under the organization key. Nothing in the
//!    registration flow reads it back; it exists so an organization-key holder can re-wrap the
//!    connector's key during an organization-key rotation.
//!
//! # Why the derivation constants are what they are
//!
//! [`DERIVE_NAME`] and [`DERIVE_INFO`] must match what the connector computes from its token, or
//! the connector derives a different key, `encryptedPayload` fails to decrypt, and it can never
//! authenticate. They are the same pair Secrets Manager access tokens use - see
//! [`AccessToken`](bitwarden_core::auth::AccessToken), which parses the identical format - and the
//! same pair the access connector's own token parser uses.
//!
//! This is the single definition of that contract. It previously lived in the web client in
//! TypeScript, with a different `info` string, which meant a connector registered from the web
//! derived a key the connector itself could not reproduce.
//!
//! # Handling the result
//!
//! The token is returned exactly once and is never recoverable: the server stores only a hash of
//! the client secret, and the seed never leaves this function except inside the token. A caller
//! must show it once for the operator to copy and must not persist or log it. Losing it means
//! deleting the connector and registering again.

use std::{fmt, str::FromStr};

use bitwarden_core::{OrganizationId, key_management::SymmetricKeySlotId};
use bitwarden_crypto::{
    EncString, PrimitiveEncryptable, SymmetricCryptoKey, derive_shareable_key,
    generate_random_bytes,
};
use bitwarden_encoding::{B64, NotB64EncodedError};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{connectors::AccessConnectorsClient, error::RotationError};

/// Key-derivation name. Combined by `derive_shareable_key` into the HKDF salt
/// `bitwarden-accesstoken`.
///
/// Contract with the connector - see the module docs before changing.
const DERIVE_NAME: &str = "accesstoken";

/// Key-derivation info, used as the HKDF `info` parameter.
///
/// Contract with the connector - see the module docs before changing.
const DERIVE_INFO: &str = "sm-access-token";

/// The token version prefix. `0` is the only version the connector accepts.
const TOKEN_VERSION: &str = "0";

/// The token's client-kind segment. The connector builds its OAuth `client_id` as
/// `access-connector.<api_key_id>`, so this segment and that prefix have to agree.
const TOKEN_CLIENT_KIND: &str = "access-connector";

/// The locally-derived half of a registration, held between generating the key material and
/// assembling the token around the server's response.
pub(super) struct RegistrationSecrets {
    /// The organization key, encrypted under the derived key. Sent to the server as
    /// `encryptedPayload`.
    pub(super) encrypted_payload: EncString,
    /// The derived key's base64, encrypted under the organization key. Sent to the server as
    /// `key`.
    pub(super) key: EncString,
    /// The raw seed, base64-encoded. Never sent to the server - it goes only into the token.
    seed_b64: B64,
}

impl RegistrationSecrets {
    /// Assembles the one-time connector token from the server's response and the local seed.
    ///
    /// Format: `0.access-connector.<api-key-id>.<client-secret>:<b64-seed>`.
    ///
    /// Consumes `self` so the seed cannot be used to mint a second token for the same connector.
    pub(super) fn into_token(self, api_key_id: Uuid, client_secret: &str) -> String {
        format!(
            "{TOKEN_VERSION}.{TOKEN_CLIENT_KIND}.{api_key_id}.{client_secret}:{}",
            self.seed_b64
        )
    }
}

/// Reasons a connector token string could not be parsed.
///
/// Not `PartialEq`: the base64 variant wraps
/// [`NotB64EncodedError`], which does not implement it.
#[derive(Debug, Error)]
pub enum ConnectorTokenInvalidError {
    /// The token did not split into a `:`-separated prefix and seed, or the prefix did not have
    /// exactly four dot-separated segments.
    #[error("Has the wrong number of parts")]
    WrongParts,
    /// The version segment was not `0`.
    #[error("Is the wrong version")]
    WrongVersion,
    /// The client-kind segment was not `access-connector`.
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
        /// The length actually decoded.
        got: usize,
    },
}

/// A parsed connector token.
///
/// This is the *consumer* half of registration, and it lives next to
/// [`RegistrationSecrets::into_token`] on purpose: the token format and the key derivation are one
/// contract, and splitting them across crates is what let the derivation constants drift in the
/// first place. The access connector carries its own copy of this parser and should converge on
/// this one.
pub struct ConnectorToken {
    /// The API key identifier. The connector's OAuth `client_id` is
    /// `access-connector.<api_key_id>`.
    pub api_key_id: Uuid,
    /// The OAuth client secret. Redacted from [`fmt::Debug`].
    pub client_secret: String,
    /// The key derived from the token's seed, which decrypts the registration payload to recover
    /// the organization key.
    pub encryption_key: SymmetricCryptoKey,
}

// Redacts the secret and the key; only the identifier is safe to log.
impl fmt::Debug for ConnectorToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectorToken")
            .field("api_key_id", &self.api_key_id)
            .finish_non_exhaustive()
    }
}

impl FromStr for ConnectorToken {
    type Err = ConnectorTokenInvalidError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let (prefix, seed_b64) = token
            .split_once(':')
            .ok_or(ConnectorTokenInvalidError::WrongParts)?;

        let [version, client_kind, api_key_id, client_secret]: [&str; 4] = prefix
            .split('.')
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| ConnectorTokenInvalidError::WrongParts)?;

        if version != TOKEN_VERSION {
            return Err(ConnectorTokenInvalidError::WrongVersion);
        }

        if client_kind != TOKEN_CLIENT_KIND {
            return Err(ConnectorTokenInvalidError::WrongPrefix);
        }

        let api_key_id = api_key_id
            .parse()
            .map_err(|_| ConnectorTokenInvalidError::InvalidUuid)?;

        let seed: B64 = seed_b64.parse()?;
        let seed: Zeroizing<[u8; 16]> =
            Zeroizing::new(seed.as_bytes().try_into().map_err(|_| {
                ConnectorTokenInvalidError::InvalidLength {
                    expected: 16,
                    got: seed.as_bytes().len(),
                }
            })?);

        Ok(Self {
            api_key_id,
            client_secret: client_secret.to_owned(),
            encryption_key: SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
                seed,
                DERIVE_NAME,
                Some(DERIVE_INFO),
            )),
        })
    }
}

impl AccessConnectorsClient {
    /// Generates the key material a connector registration needs.
    ///
    /// Fails with [`MissingOrganizationKey`](RotationError::MissingOrganizationKey) when the
    /// caller's key store holds no key for the organization - they are not a member of it, or the
    /// store has not been populated. Registration cannot proceed without it, since the whole point
    /// is to hand that key to the connector.
    pub(super) fn registration_secrets(
        &self,
        organization_id: OrganizationId,
    ) -> Result<RegistrationSecrets, RotationError> {
        let organization_key = SymmetricKeySlotId::Organization(organization_id);
        let mut ctx = self.key_store.context_mut();

        if !ctx.has_symmetric_key(organization_key) {
            return Err(RotationError::MissingOrganizationKey);
        }

        let seed: Zeroizing<[u8; 16]> = generate_random_bytes();
        let seed_b64 = B64::from(seed.as_slice());

        let derived_key = ctx.derive_shareable_key(seed, DERIVE_NAME, Some(DERIVE_INFO))?;

        // The payload hands the connector the organization key itself, so it is encrypted under the
        // derived key - the one secret only the token holder can reproduce.
        #[allow(deprecated)]
        let organization_key_b64 = ctx
            .dangerous_get_symmetric_key(organization_key)?
            .to_base64();
        let payload = serde_json::json!({ "encryptionKey": organization_key_b64.to_string() });
        let encrypted_payload = payload.to_string().encrypt(&mut ctx, derived_key)?;

        #[allow(deprecated)]
        let derived_key_b64 = ctx.dangerous_get_symmetric_key(derived_key)?.to_base64();
        let key = derived_key_b64
            .to_string()
            .encrypt(&mut ctx, organization_key)?;

        Ok(RegistrationSecrets {
            encrypted_payload,
            key,
            seed_b64,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::{
        client::ApiConfigurations,
        key_management::{
            create_test_crypto_with_user_and_org_key, create_test_crypto_with_user_key,
        },
    };
    use bitwarden_crypto::{Decryptable, SymmetricKeyAlgorithm};
    use uuid::uuid;

    use super::*;

    fn organization_id() -> OrganizationId {
        OrganizationId::new(uuid!("11111111-1111-1111-1111-111111111111"))
    }

    fn client_with_org_key(organization_key: SymmetricCryptoKey) -> AccessConnectorsClient {
        AccessConnectorsClient {
            key_store: create_test_crypto_with_user_and_org_key(
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                organization_id(),
                organization_key,
            ),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(
                ApiClient::new_mocked(|_| {}),
            )),
        }
    }

    /// The contract that matters: the connector re-derives its key from the seed in the token
    /// alone, then decrypts `encryptedPayload` to recover the organization key. This walks that
    /// path using [`ConnectorToken`], the parser a connector uses - so if the mint and parse
    /// halves of this contract ever drift apart, this fails.
    #[test]
    fn a_connector_recovers_the_organization_key_from_its_token_alone() {
        let organization_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let client = client_with_org_key(organization_key.clone());

        let secrets = client
            .registration_secrets(organization_id())
            .expect("the org key is in the store");
        let encrypted_payload = secrets.encrypted_payload.clone();

        let api_key_id = uuid!("22222222-2222-2222-2222-222222222222");
        let token = secrets.into_token(api_key_id, "client-secret-value");

        // Everything below is what a connector does with nothing but the token string.
        let parsed = ConnectorToken::from_str(&token).expect("the token parses");
        assert_eq!(parsed.api_key_id, api_key_id);
        assert_eq!(parsed.client_secret, "client-secret-value");

        let connector_store = create_test_crypto_with_user_key(parsed.encryption_key);
        let mut ctx = connector_store.context();
        let payload: String = encrypted_payload
            .decrypt(&mut ctx, SymmetricKeySlotId::User)
            .expect("the derived key decrypts the payload");

        let recovered: serde_json::Value =
            serde_json::from_str(&payload).expect("the payload is JSON");
        assert_eq!(
            recovered["encryptionKey"].as_str(),
            Some(organization_key.to_base64().to_string().as_str()),
            "the connector must recover the organization key verbatim"
        );
    }

    #[test]
    fn the_token_has_the_format_the_connector_parses() {
        let client = client_with_org_key(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        ));
        let secrets = client
            .registration_secrets(organization_id())
            .expect("the org key is in the store");

        let api_key_id = uuid!("22222222-2222-2222-2222-222222222222");
        let token = secrets.into_token(api_key_id, "secret");

        let (prefix, seed_b64) = token.split_once(':').expect("a `:` separates the seed");
        assert_eq!(prefix, format!("0.access-connector.{api_key_id}.secret"));

        // The connector requires exactly 16 bytes; a different length is rejected at parse time.
        let seed: B64 = seed_b64.parse().expect("the suffix is base64");
        assert_eq!(seed.as_bytes().len(), 16);
    }

    /// The `key` field is not read during registration, so a mistake in it would go unnoticed until
    /// an organization-key rotation. It must be the derived key's base64, wrapped under the
    /// organization key.
    #[test]
    fn the_key_field_wraps_the_derived_key_under_the_organization_key() {
        let organization_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let client = client_with_org_key(organization_key.clone());

        let secrets = client
            .registration_secrets(organization_id())
            .expect("the org key is in the store");
        let key_field = secrets.key.clone();
        let token = secrets.into_token(uuid!("22222222-2222-2222-2222-222222222222"), "secret");

        let mut ctx = client.key_store.context();
        let wrapped: String = key_field
            .decrypt(
                &mut ctx,
                SymmetricKeySlotId::Organization(organization_id()),
            )
            .expect("the org key unwraps the key field");

        let derived_from_token = ConnectorToken::from_str(&token)
            .expect("the token parses")
            .encryption_key;
        assert_eq!(
            wrapped,
            derived_from_token.to_base64().to_string(),
            "the key field must hold the same derived key the token produces"
        );
    }

    /// Each registration must mint fresh material, or two connectors would share a key and revoking
    /// one would not lock out the other.
    #[test]
    fn each_registration_generates_a_distinct_seed() {
        let client = client_with_org_key(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        ));
        let api_key_id = uuid!("22222222-2222-2222-2222-222222222222");

        let first = client
            .registration_secrets(organization_id())
            .expect("the org key is in the store")
            .into_token(api_key_id, "secret");
        let second = client
            .registration_secrets(organization_id())
            .expect("the org key is in the store")
            .into_token(api_key_id, "secret");

        assert_ne!(first, second);
    }

    #[test]
    fn registering_without_the_organization_key_fails_before_any_network_call() {
        let client = AccessConnectorsClient {
            // A store with a user key but no organization key - the caller is not a member.
            key_store: create_test_crypto_with_user_key(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            )),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(
                ApiClient::new_mocked(|_| {}),
            )),
        };

        let result = client.registration_secrets(organization_id());

        assert!(matches!(result, Err(RotationError::MissingOrganizationKey)));
    }
}
