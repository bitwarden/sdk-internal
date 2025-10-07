use bitwarden_crypto::{CryptoError, HashPurpose, Kdf, MasterKey};

mod policy;
use bitwarden_encoding::B64;
pub use policy::MasterPasswordPolicyOptions;
pub(crate) use policy::satisfies_policy;
mod validate;
pub(crate) use validate::{validate_password, validate_password_user_key};
mod strength;
pub(crate) use strength::password_strength;

pub(crate) fn determine_password_hash(
    email: &str,
    kdf: &Kdf,
    password: &str,
    purpose: HashPurpose,
) -> Result<B64, CryptoError> {
    let master_key = MasterKey::derive(password, email, kdf)?;
    Ok(master_key.derive_master_key_hash(password.as_bytes(), purpose))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    #[test]
    fn test_determine_password_hash() {
        use super::determine_password_hash;

        let password = "password123";
        let email = "test@bitwarden.com";
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(100_000).unwrap(),
        };
        let purpose = HashPurpose::LocalAuthorization;

        let result = determine_password_hash(email, &kdf, password, purpose).unwrap();

        assert_eq!(
            result.to_string(),
            "7kTqkF1pY/3JeOu73N9kR99fDDe9O1JOZaVc7KH3lsU="
        );
    }
}
