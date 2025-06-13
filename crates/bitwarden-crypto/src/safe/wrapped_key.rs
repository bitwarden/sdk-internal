use std::marker::PhantomData;

use crate::{CryptoError, KeyIds, KeyStoreContext};

/// A wrapped symmetric key is a symmetric key that has been wrapped using another symmetric key.
/// This struct provides a well-defined interface for wrapping, unwrapping, and rewrapping symmetric keys.
pub(crate) struct WrappedSymmetricKey<Ids: KeyIds> {
    _phantom: PhantomData<Ids>,
}

impl<Ids: KeyIds> WrappedSymmetricKey<Ids> {
    /// Wraps a symmetric key using the provided wrapping key, and sets it to the provided key store context keyslot.
    pub(crate) fn wrap(
        ctx: &KeyStoreContext<Ids>,
        wrapping_key: Ids::Symmetric,
        key_to_wrap: Ids::Symmetric,
    ) -> Self {
        unimplemented!()
    }

    /// Unwraps the wrapped key using the provided wrapping key, and sets it to the provided key store context keyslot.
    pub(crate) fn unwrap(
        &self,
        ctx: &KeyStoreContext<Ids>,
        wrapping_key: Ids::Symmetric,
    ) -> Result<Ids::Symmetric, CryptoError> {
        unimplemented!()
    }

    /// Rewraps the wrapped key with a new wrapping key. This can be used for key-rotation.
    pub(crate) fn rewrap(
        &self,
        ctx: &KeyStoreContext<Ids>,
        old_wrapping_key: Ids::Symmetric,
        new_wrapping_key: Ids::Symmetric,
    ) -> Result<Self, CryptoError> {
        unimplemented!()
    }
}
