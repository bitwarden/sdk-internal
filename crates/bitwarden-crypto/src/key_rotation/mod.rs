use crate::{
    CoseKeyBytes, CoseSerializable, CoseSign1Bytes, CryptoError, EncString, KeyEncryptable,
    KeyStoreContext, SpkiPublicKeyBytes, SymmetricCryptoKey,
};

/// Rotated set of account keys
pub struct RotatedUserKeys {
    /// The verifying key
    pub verifying_key: CoseKeyBytes,
    /// Signing key, encrypted with a symmetric key (user key, org key)
    pub signing_key: EncString,
    /// The user's public key, signed by the signing key
    pub signed_public_key: CoseSign1Bytes,
    /// The user's public key, without signature
    pub public_key: SpkiPublicKeyBytes,
    /// The user's private key, encrypted with the user key
    pub private_key: EncString,
}

/// Re-encrypts the user's keys with the provided symmetric key for a v2 user.
pub(crate) fn get_v2_rotated_account_keys<Ids: crate::KeyIds>(
    new_user_key: SymmetricCryptoKey,
    current_user_private_key_id: Ids::Asymmetric,
    current_user_signing_key_id: Ids::Signing,
    ctx: &KeyStoreContext<Ids>,
) -> Result<RotatedUserKeys, CryptoError> {
    let signing_key = ctx.get_signing_key(current_user_signing_key_id)?;
    let private_key = ctx.get_asymmetric_key(current_user_private_key_id)?;
    let signed_public_key =
        ctx.make_signed_public_key(current_user_private_key_id, current_user_signing_key_id)?;

    Ok(RotatedUserKeys {
        verifying_key: signing_key.to_verifying_key().to_cose(),
        signing_key: signing_key.to_cose().encrypt_with_key(&new_user_key)?,
        signed_public_key: signed_public_key.into(),
        public_key: private_key.to_public_key().to_der()?,
        private_key: private_key.to_der()?.encrypt_with_key(&new_user_key)?,
    })
}
