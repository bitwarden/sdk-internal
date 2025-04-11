use bitwarden_crypto::{CryptoError, HashPurpose, Kdf, MasterKey};

pub(super) async fn hash_password(
    email: String,
    password: String,
    kdf_params: Kdf,
    purpose: HashPurpose,
) -> Result<String, CryptoError> {
    let master_key = MasterKey::derive(&password, &email, &kdf_params)?;

    master_key.derive_master_key_hash(password.as_bytes(), purpose)
}
