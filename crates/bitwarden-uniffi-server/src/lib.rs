#![doc = include_str!("../README.md")]

uniffi::setup_scaffolding!();

mod crypto_parsing;
mod error;
mod inspection;

pub use crypto_parsing::CryptoParsingClient;
pub use error::ServerError;
pub use inspection::{
    CryptoObjectKeyIds, EncStringAlgorithm, EncStringInfo, PublicKeyAlgorithm, PublicKeyInfo,
    UnsignedSharedKeyAlgorithm, UnsignedSharedKeyInfo, VerifyingKeyAlgorithm, VerifyingKeyInfo,
};

/// Entry point of the server bindings.
#[derive(uniffi::Object, Default)]
pub struct ServerClient;

#[uniffi::export]
impl ServerClient {
    /// Creates a new client.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// Parses SDK crypto objects and reads the key ids they name, without decrypting.
    pub fn crypto_parsing(&self) -> CryptoParsingClient {
        CryptoParsingClient
    }
}
