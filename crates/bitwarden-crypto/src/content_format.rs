use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

/// The content format describes the format of the contained bytes. Message encryption always
/// happens on the byte level, and this allows determining what format the contained data has. For
/// instance, an `EncString` in most cases contains UTF-8 encoded text. In some cases it may contain
/// a Pkcs8 private key, or a COSE key. Specifically, for COSE keys, this allows distinguishing
/// between the old symmetric key format, represented as `ContentFormat::OctetStream`, and the new
/// COSE key format, represented as `ContentFormat::CoseKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum ContentFormat {
    /// UTF-8 encoded text
    Utf8,
    /// Pkcs8 private key DER
    Pkcs8,
    /// COSE serialized CoseKey
    CoseKey,
    /// Bitwarden Legacy Key
    /// There are three permissible byte values here:
    /// - `[u8; 32]` - AES-CBC (no hmac) key. This is to be removed and banned.
    /// - `[u8; 64]` - AES-CBC with HMAC key. This is the v1 userkey key type
    /// - `[u8; >64]` - COSE key. Padded to be larger than 64 bytes.
    BitwardenLegacyKey,
    /// Stream of bytes
    OctetStream,
}
