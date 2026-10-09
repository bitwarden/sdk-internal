//! Minting an access token's key material (the issuer side).

use bitwarden_crypto::{EncString, KeySlotIds, KeyStoreContext, PrimitiveEncryptable};
use zeroize::Zeroizing;

use crate::{AccessTokenError, AccessTokenSeed, key::DERIVE_NAME, purpose::KeyPurpose};

/// Key material for a new access-token registration.
pub struct AccessTokenKeyMaterial {
    /// The organization key, encrypted under the derived key, for the token holder.
    pub encrypted_payload: EncString,
    /// The derived key's base64, encrypted under the organization key, so the organization can
    /// recover it without the token.
    pub key: EncString,
    /// Only reachable through [`Self::into_seed`].
    seed: AccessTokenSeed,
}

impl AccessTokenKeyMaterial {
    /// Consumes the key material to recover its seed.
    pub fn into_seed(self) -> AccessTokenSeed {
        self.seed
    }
}

/// Generates a random seed, derives the key for `purpose`, and wraps the organization key for the
/// token holder and the derived key for the organization.
///
/// A missing `organization_key` surfaces as [`AccessTokenError::Crypto`].
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

    // Encrypted under the derived key, which only the token holder can reproduce.
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
