use bitwarden_crypto::{CryptoError, HashPurpose, Kdf, MasterKey};
use bitwarden_encoding::B64;
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};

pub(super) async fn hash_password(
    email: String,
    password: SensitiveString,
    kdf_params: Kdf,
    purpose: HashPurpose,
) -> Result<B64, CryptoError> {
    let master_key = MasterKey::derive(&password, &email, &kdf_params)?;

    // EXPOSE: The password bytes are fed into the master key hash (PBKDF2) primitive, which does
    // not log them.
    Ok(master_key.derive_master_key_hash(password.expose().as_bytes(), purpose))
}
