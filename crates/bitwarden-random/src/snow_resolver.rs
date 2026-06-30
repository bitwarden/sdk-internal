use snow::{
    Error,
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};

use crate::SdkRngImpl;

impl Random for SdkRngImpl {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        rand::Rng::fill_bytes(self, dest);
        Ok(())
    }
}

/// A snow [`CryptoResolver`] that supplies the SDK's [`SdkRngImpl`]
#[derive(Default)]
pub struct SdkCryptoResolver;

impl CryptoResolver for SdkCryptoResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(SdkRngImpl::default()))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
    // `resolve_kem` is behind snow's `hfs` feature (not enabled); its default returns None.
}
