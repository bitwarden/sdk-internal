//! Minting an access token (the issuer side): a thin wrapper around
//! `bitwarden-access-token-crypto`'s key material that also assembles the wire string.

use bitwarden_access_token_crypto::{AccessTokenSeed, make_access_token_key_material};
use bitwarden_crypto::{EncString, KeySlotIds, KeyStoreContext};
use bitwarden_encoding::B64;
use uuid::Uuid;

use crate::{AccessTokenError, AccessTokenKind, consts::TOKEN_VERSION};

/// The locally-derived half of a registration, held between generating the key material and
/// assembling the token around the issuer's response (e.g. a freshly allocated API key id and
/// client secret).
pub struct AccessTokenSecrets {
    /// The organization key, encrypted under the derived key. Sent to the issuing server as
    /// `encryptedPayload`.
    pub encrypted_payload: EncString,
    /// The derived key's base64, encrypted under the organization key. Sent to the issuing server
    /// as `key`.
    pub key: EncString,
    /// The raw seed. Reachable only by consuming `self` through [`Self::into_token`], so it cannot
    /// mint a second token for the same credential.
    seed: AccessTokenSeed,
    /// Which kind the key was derived for; `into_token` builds the matching wire shape and uses
    /// this rather than trusting a caller-supplied kind that might not match.
    kind: AccessTokenKind,
}

impl AccessTokenSecrets {
    /// Assembles the one-time token: `0.<kind>.<api-key-id>.<client-secret>:<b64-seed>` when this
    /// credential's kind has a wire segment, or `0.<api-key-id>.<client-secret>:<b64-seed>`
    /// otherwise (Secrets Manager).
    ///
    /// Consumes `self` so the seed cannot mint a second token for the same credential.
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

/// Generates the key material for an access-token registration: a random 16-byte seed, the key
/// derived from it for `kind`, and the organization key wrapped both for the token holder
/// (`encrypted_payload`) and for the organization itself (`key`).
///
/// `organization_key` must already resolve in `ctx`; callers that want a dedicated error for a
/// missing key should check [`KeyStoreContext::has_symmetric_key`] first; otherwise this surfaces
/// as [`AccessTokenError::Crypto`].
pub fn make_access_token_secrets<Ids: KeySlotIds>(
    ctx: &mut KeyStoreContext<Ids>,
    organization_key: Ids::Symmetric,
    kind: AccessTokenKind,
) -> Result<AccessTokenSecrets, AccessTokenError> {
    let material = make_access_token_key_material(ctx, organization_key, kind.key_purpose())?;

    // `AccessTokenKeyMaterial`'s seed is private and reachable only by consuming the material
    // through `into_seed`, so the public fields are copied out first.
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
