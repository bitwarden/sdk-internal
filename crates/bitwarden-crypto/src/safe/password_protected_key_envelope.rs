use std::marker::PhantomData;

use crate::{Kdf, KeyIds, KeyStoreContext};

/// A password-protected key envelope can seal a symmetric key, and protect it with a password. It does so
/// by using a Key Derivation Function (KDF), to increase the difficulty of brute-forcing the password.
///
/// The KDF parameters such as iterations and salt are stored in the key-envelope and do not have to be provided.
/// When creating a new password-protected key envelope, custom parameters can be optionally provided on creation.
pub(crate) struct PasswordProtectedKeyEnvelope<Ids: KeyIds> {
    _phantom: PhantomData<Ids>,
}

impl<Ids: KeyIds> PasswordProtectedKeyEnvelope<Ids> {
    /// Seals a symmetric key with a password, using the current default KDF parameters and a random salt.
    pub(crate) fn seal(
        key_to_seal: Ids::Symmetric,
        password: &str,
        ctx: &KeyStoreContext<Ids>,
    ) -> Self {
        // KDF = default kdf - hardcoded
        let kdf = Kdf::default();
        Self::seal_with_custom_kdf(key_to_seal, password, &kdf, ctx)
    }

    /// Seals a symmetric key with custom KDF difficulty, and a random salt.
    pub(crate) fn seal_with_custom_kdf(
        key_to_seal: Ids::Symmetric,
        password: &str,
        kdf_settings: &Kdf,
        ctx: &KeyStoreContext<Ids>,
    ) -> Self {
        // KDF = CURRENT_DEFAULT_KDF
        // SALT = RANDOM
        // Store KDF + SALT in the Cose Encrypt0 headers
        // Then, derive key with kdf, wrap the symmetric key with the derived key, and store it in the CoseEncrypt0 payload.
        unimplemented!()
    }

    /// Unseals a symmetric key from the password-protected envelope, and stores it in the key store context.
    pub(crate) fn unseal(
        &self,
        target_keyslot: Ids::Symmetric,
        password: &str,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<(), crate::CryptoError> {
        // KDF and SALT are stored in the CoseEncrypt0 headers
        // Derive the key with the KDF and SALT, then unwrap the symmetric key from the CoseEncrypt0 payload.
        unimplemented!()
    }
}
