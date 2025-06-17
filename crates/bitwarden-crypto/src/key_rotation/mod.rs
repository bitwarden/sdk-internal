use base64::{engine::general_purpose::STANDARD, Engine};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;

use crate::{
    ContentFormat, CoseSerializable, CryptoError, EncString, KeyEncryptable, KeyStoreContext,
    SymmetricCryptoKey,
};

/// Rotated set of account keys
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct RotateUserKeysResponse {
    /// The verifying key
    verifying_key: String,
    /// Signing key, encrypted with a symmetric key (user key, org key)
    signing_key: EncString,
    /// The user's public key, signed by the signing key
    signed_public_key: String,
    // The user's public key, without signature
    public_key: String,
    // The user's private key, encrypted with the user key
    private_key: EncString,
}

/// Re-encrypts the user's keys with the provided symmetric key.
pub fn get_rotated_account_keys<Ids: crate::KeyIds>(
    new_user_key: SymmetricCryptoKey,
    current_user_private_key_id: Ids::Asymmetric,
    current_user_signing_key_id: Ids::Signing,
    ctx: &KeyStoreContext<Ids>,
) -> Result<RotateUserKeysResponse, CryptoError> {
    let signing_key = ctx.get_signing_key(current_user_signing_key_id)?;
    let private_key = ctx.get_asymmetric_key(current_user_private_key_id)?;
    let signed_public_key: Vec<u8> = ctx
        .make_signed_public_key(current_user_private_key_id, current_user_signing_key_id)?
        .into();

    Ok(RotateUserKeysResponse {
        verifying_key: STANDARD.encode(signing_key.to_verifying_key().to_cose()),
        signing_key: signing_key
            .to_cose()
            .encrypt_with_key(&new_user_key, ContentFormat::CoseKey)?,
        signed_public_key: STANDARD.encode(&signed_public_key),
        public_key: STANDARD.encode(private_key.to_public_key().to_der()?),
        private_key: private_key
            .to_der()?
            .encrypt_with_key(&new_user_key, ContentFormat::Pkcs8)?,
    })
}
