use crate::{
    AsymmetricCryptoKey, CoseKeyBytes, CoseSerializable, CoseSign1Bytes, CryptoError, EncString,
    KeyEncryptable, SignedPublicKeyMessage, SigningKey, SpkiPublicKeyBytes, SymmetricCryptoKey,
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
pub(crate) fn get_v2_rotated_account_keys(
    new_user_key: &SymmetricCryptoKey,
    current_private_key: &AsymmetricCryptoKey,
    current_signing_key: &SigningKey,
) -> Result<RotatedUserKeys, CryptoError> {
    let signed_public_key =
        SignedPublicKeyMessage::from_public_key(&current_private_key.to_public_key())?
            .sign(current_signing_key)?;
    Ok(RotatedUserKeys {
        verifying_key: current_signing_key.to_verifying_key().to_cose(),
        signing_key: current_signing_key
            .to_cose()
            .encrypt_with_key(new_user_key)?,
        signed_public_key: signed_public_key.into(),
        public_key: current_private_key.to_public_key().to_der()?,
        private_key: current_private_key
            .to_der()?
            .encrypt_with_key(new_user_key)?,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        KeyDecryptable, Pkcs8PrivateKeyBytes, PublicKeyEncryptionAlgorithm, SignatureAlgorithm,
    };

    use super::*;

    #[test]
    fn test_get_v2_rotated_account_keys() {
        let new_user_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let current_private_key =
            AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let current_signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let rotated_keys =
            get_v2_rotated_account_keys(&new_user_key, &current_private_key, &current_signing_key)
                .expect("Failed to rotate keys");

        let decrypted_signing_key: Vec<u8> = rotated_keys
            .signing_key
            .decrypt_with_key(&new_user_key)
            .expect("Failed to decrypt signing key");
        let decrypted_signing_key =
            SigningKey::from_cose(&CoseKeyBytes::from(decrypted_signing_key))
                .expect("Failed to parse signing key");
        let decrypted_private_key: Vec<u8> = rotated_keys
            .private_key
            .decrypt_with_key(&new_user_key)
            .expect("Failed to decrypt private key");
        let decrypted_private_key =
            AsymmetricCryptoKey::from_der(&Pkcs8PrivateKeyBytes::from(decrypted_private_key))
                .expect("Failed to parse private key");

        assert_eq!(
            decrypted_signing_key.to_verifying_key().to_cose(),
            rotated_keys.verifying_key
        );
        assert_eq!(
            decrypted_signing_key.to_verifying_key().to_cose(),
            current_signing_key.to_verifying_key().to_cose()
        );
        assert_eq!(
            decrypted_signing_key.to_cose(),
            current_signing_key.to_cose()
        );

        assert_eq!(
            decrypted_private_key.to_public_key().to_der().unwrap(),
            rotated_keys.public_key
        );
        assert_eq!(
            decrypted_private_key.to_public_key().to_der().unwrap(),
            current_private_key.to_public_key().to_der().unwrap()
        );
        assert_eq!(
            decrypted_private_key.to_der().unwrap(),
            current_private_key.to_der().unwrap()
        );
    }
}
