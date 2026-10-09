//! Minting an access token (the issuer side).

use bitwarden_access_token_crypto::{AccessTokenSeed, make_access_token_key_material};
use bitwarden_crypto::{EncString, KeySlotIds, KeyStoreContext};
use bitwarden_encoding::B64;
use uuid::Uuid;

use crate::{AccessTokenError, AccessTokenKind, consts::TOKEN_VERSION};

/// Registration secrets, held until the issuer allocates an API key id and client secret.
pub struct AccessTokenSecrets {
    /// The organization key, encrypted under the derived key. Sent as `encryptedPayload`.
    pub encrypted_payload: EncString,
    /// The derived key's base64, encrypted under the organization key. Sent as `key`.
    pub key: EncString,
    seed: AccessTokenSeed,
    /// The kind the key was derived for, so `into_token` cannot build a mismatched shape.
    kind: AccessTokenKind,
}

impl AccessTokenSecrets {
    /// Assembles `0.<kind>.<api-key-id>.<client-secret>:<b64-seed>`, omitting `<kind>` for
    /// Secrets Manager. Consumes `self` so the seed cannot mint a second token.
    pub fn into_token(self, api_key_id: Uuid, client_secret: &str) -> String {
        let seed_b64 = B64::from(self.seed.as_bytes().as_slice());
        match self.kind.segment() {
            Some(segment) => {
                format!("{TOKEN_VERSION}.{segment}.{api_key_id}.{client_secret}:{seed_b64}")
            }
            None => format!("{TOKEN_VERSION}.{api_key_id}.{client_secret}:{seed_b64}"),
        }
    }
}

/// Generates the registration secrets for a `kind` access token.
///
/// A missing `organization_key` surfaces as [`AccessTokenError::Crypto`].
pub fn make_access_token_secrets<Ids: KeySlotIds>(
    ctx: &mut KeyStoreContext<Ids>,
    organization_key: Ids::Symmetric,
    kind: AccessTokenKind,
) -> Result<AccessTokenSecrets, AccessTokenError> {
    let material = make_access_token_key_material(ctx, organization_key, kind.key_purpose())?;

    // `into_seed` consumes the material, so copy the public fields out first.
    let encrypted_payload = material.encrypted_payload.clone();
    let key = material.key.clone();
    let seed = material.into_seed();

    Ok(AccessTokenSecrets {
        encrypted_payload,
        key,
        seed,
        kind,
    })
}
