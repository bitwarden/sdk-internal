//! Minting an access token's key material (the issuer side).

use bitwarden_crypto::{
    EncString, KeySlotIds, KeyStoreContext, PrimitiveEncryptable, generate_random_bytes,
};
use bitwarden_encoding::B64;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AccessTokenError, AccessTokenKind,
    consts::{DERIVE_NAME, TOKEN_VERSION},
};

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
    /// The raw seed, base64-encoded. It goes only into the token, never to the server.
    seed_b64: B64,
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
        match self.kind.segment() {
            Some(segment) => format!(
                "{TOKEN_VERSION}.{segment}.{api_key_id}.{client_secret}:{}",
                self.seed_b64
            ),
            None => format!(
                "{TOKEN_VERSION}.{api_key_id}.{client_secret}:{}",
                self.seed_b64
            ),
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
    let seed: Zeroizing<[u8; 16]> = generate_random_bytes();
    let seed_b64 = B64::from(seed.as_slice());

    let derived_key = ctx.derive_shareable_key(seed, DERIVE_NAME, Some(kind.derive_info()))?;

    // The payload hands the token holder the organization key itself, so it is encrypted under the
    // derived key, which only they can reproduce.
    #[allow(deprecated)]
    let organization_key_b64 = ctx
        .dangerous_get_symmetric_key(organization_key)?
        .to_base64();
    let payload = serde_json::json!({ "encryptionKey": organization_key_b64.to_string() });
    let encrypted_payload = payload.to_string().encrypt(ctx, derived_key)?;

    #[allow(deprecated)]
    let derived_key_b64 = ctx.dangerous_get_symmetric_key(derived_key)?.to_base64();
    let key = derived_key_b64.to_string().encrypt(ctx, organization_key)?;

    Ok(AccessTokenSecrets {
        encrypted_payload,
        key,
        seed_b64,
        kind,
    })
}
