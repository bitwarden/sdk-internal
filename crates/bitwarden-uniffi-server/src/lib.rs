#![doc = include_str!("../README.md")]

uniffi::setup_scaffolding!();

mod crypto_parsing;
mod error;
mod inspection;
mod key_data;

pub use crypto_parsing::CryptoParsingClient;
pub use error::ServerError;
pub use inspection::{
    CryptoObjectKeyIds, EncStringAlgorithm, EncStringInfo, PublicKeyAlgorithm, PublicKeyInfo,
    UnsignedSharedKeyAlgorithm, UnsignedSharedKeyInfo, VerifyingKeyAlgorithm, VerifyingKeyInfo,
};
pub use key_data::{
    KeyDataClient, KeyDataType, KeyIds, KeyInfo, UnlockMethodInfo, UnlockMethodKind,
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

    /// Parses and validates the key service's key and unlock method `data`.
    pub fn key_data(&self) -> KeyDataClient {
        KeyDataClient
    }
}
