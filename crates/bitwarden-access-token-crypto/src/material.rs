//! Minting an access token's key material (the issuer side).

use bitwarden_crypto::{EncString, KeySlotIds, KeyStoreContext, PrimitiveEncryptable};
use zeroize::Zeroizing;

use crate::{AccessTokenError, AccessTokenSeed, key::DERIVE_NAME, purpose::KeyPurpose};

/// Key material minted for a fresh access-token registration: the organization key wrapped both
/// for the token holder (`encrypted_payload`) and for the organization itself (`key`), plus the
/// seed the two were derived from.
pub struct AccessTokenKeyMaterial {
    /// The organization key, encrypted under the derived key. Handed to the token holder, who
    /// recovers it with [`crate::AccessTokenKey::open_payload`].
    pub encrypted_payload: EncString,
    /// The derived key's base64, encrypted under the organization key. Lets the organization
    /// recover the derived key later without needing the credential itself.
    pub key: EncString,
    /// The seed this key material was derived from. Private: reachable only by consuming the
    /// material through [`Self::into_seed`], so a caller cannot read it without deliberately
    /// taking ownership of it.
    seed: AccessTokenSeed,
}

impl AccessTokenKeyMaterial {
    /// Consumes the key material to recover its seed, e.g. so a caller can encode it into its own
    /// wire format. Consuming (rather than borrowing) makes it awkward to accidentally read the
    /// seed more than once.
    pub fn into_seed(self) -> AccessTokenSeed {
        self.seed
    }
}

/// Generates the key material for an access-token registration: a random 16-byte seed, the key
/// derived from it for `purpose`, and the organization key wrapped both for the token holder
/// (`encrypted_payload`) and for the organization itself (`key`).
///
/// `organization_key` must already resolve in `ctx`; callers that want a dedicated error for a
/// missing key should check [`KeyStoreContext::has_symmetric_key`] first; otherwise this surfaces
/// as [`AccessTokenError::Crypto`].
pub fn make_access_token_key_material<Ids: KeySlotIds>(
    ctx: &mut KeyStoreContext<Ids>,
    organization_key: Ids::Symmetric,
    purpose: KeyPurpose,
) -> Result<AccessTokenKeyMaterial, AccessTokenError> {
    let seed = AccessTokenSeed::generate();

    let derived_key = ctx.derive_shareable_key(
        Zeroizing::new(*seed.as_bytes()),
        DERIVE_NAME,
        Some(purpose.as_str()),
    )?;

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

    Ok(AccessTokenKeyMaterial {
        encrypted_payload,
        key,
        seed,
    })
}
