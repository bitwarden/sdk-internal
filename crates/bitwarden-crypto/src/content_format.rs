use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

use crate::{
    traits::PrimitiveEncryptableWithContentType, CryptoError, EncString, KeyEncryptable,
    KeyEncryptableWithContentType, KeyIds, KeyStoreContext, PrimitiveEncryptable,
    SymmetricCryptoKey,
};

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
    Pkcs8PrivateKey,
    /// SPKI public key DER
    SPKIPublicKeyDer,
    /// COSE serialized CoseKey
    CoseKey,
    /// CoseSign1 message
    CoseSign1,
    /// Bitwarden Legacy Key
    /// There are three permissible byte values here:
    /// - `[u8; 32]` - AES-CBC (no hmac) key. This is to be removed and banned.
    /// - `[u8; 64]` - AES-CBC with HMAC key. This is the v1 userkey key type
    /// - `[u8; >64]` - COSE key. Padded to be larger than 64 bytes.
    BitwardenLegacyKey,
    /// Stream of bytes
    OctetStream,
    /// CBOR serialized data
    Cbor,
}

/// This trait is used to instantiate different typed byte vectors with a specific content format,
/// using `SerializedBytes<C>`. This allows for compile-time guarantees about the content format
/// of the serialized bytes. The exception here is the escape hatch using e.g. `from(Vec<u8>)`,
/// which can still be mis-used, but has to be misused explicitly.
pub trait ConstContentFormat {
    /// Returns the content format as a `ContentFormat` enum.
    fn content_format() -> ContentFormat;
}

/// A serialized byte array with a specific content format. This is used to represent data that has
/// a specific format, such as UTF-8 encoded text, raw bytes, or COSE keys. The content
/// format is used to determine how the bytes should be interpreted when encrypting or decrypting
/// the data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedBytes<C: ConstContentFormat> {
    inner: Vec<u8>,
    _marker: std::marker::PhantomData<C>,
}

impl<C: ConstContentFormat> From<Vec<u8>> for SerializedBytes<C> {
    fn from(inner: Vec<u8>) -> Self {
        Self {
            inner,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C: ConstContentFormat> From<&[u8]> for SerializedBytes<C> {
    fn from(inner: &[u8]) -> Self {
        Self::from(inner.to_vec())
    }
}

impl<C: ConstContentFormat> AsRef<[u8]> for SerializedBytes<C> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

/// Content format for UTF-8 encoded text. Used for most text messages.
#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) struct Utf8ContentFormat;
impl ConstContentFormat for Utf8ContentFormat {
    fn content_format() -> ContentFormat {
        ContentFormat::Utf8
    }
}

/// Content format for raw bytes. Used for attachments and send seed keys.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct OctetStreamContentFormat;
impl ConstContentFormat for OctetStreamContentFormat {
    fn content_format() -> ContentFormat {
        ContentFormat::OctetStream
    }
}

/// Content format for PKCS8 private keys in DER format.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Pkcs8PrivateKeyDerContentFormat;
impl ConstContentFormat for Pkcs8PrivateKeyDerContentFormat {
    fn content_format() -> ContentFormat {
        ContentFormat::Pkcs8PrivateKey
    }
}

/// Content format for SPKI public keys in DER format.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SpkiPublicKeyDerContentFormat;
impl ConstContentFormat for SpkiPublicKeyDerContentFormat {
    fn content_format() -> ContentFormat {
        ContentFormat::SPKIPublicKeyDer
    }
}

/// Content format for COSE keys.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CoseKeyContentFormat;
impl ConstContentFormat for CoseKeyContentFormat {
    fn content_format() -> ContentFormat {
        ContentFormat::CoseKey
    }
}
impl CoseContentFormat for CoseKeyContentFormat {}

/// A legacy content format for Bitwarden keys. See `ContentFormat::BitwardenLegacyKey`
#[allow(unused)]
#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) struct BitwardenLegacyKeyContentFormat;
impl ConstContentFormat for BitwardenLegacyKeyContentFormat {
    fn content_format() -> ContentFormat {
        ContentFormat::BitwardenLegacyKey
    }
}

/// Content format for COSE Sign1 messages.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CoseSign1ContentFormat;
impl ConstContentFormat for CoseSign1ContentFormat {
    fn content_format() -> ContentFormat {
        ContentFormat::CoseSign1
    }
}
impl CoseContentFormat for CoseSign1ContentFormat {}

/// A marker trait for COSE content formats.
pub trait CoseContentFormat {}

impl<Ids: KeyIds, T: ConstContentFormat> PrimitiveEncryptable<Ids, Ids::Symmetric, EncString>
    for SerializedBytes<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, CryptoError> {
        self.inner.encrypt(ctx, key, T::content_format())
    }
}

impl<T: ConstContentFormat> KeyEncryptable<SymmetricCryptoKey, EncString> for &SerializedBytes<T> {
    fn encrypt_with_key(self, key: &SymmetricCryptoKey) -> Result<EncString, CryptoError> {
        self.as_ref().encrypt_with_key(key, T::content_format())
    }
}

impl From<String> for SerializedBytes<Utf8ContentFormat> {
    fn from(val: String) -> Self {
        SerializedBytes::from(val.into_bytes())
    }
}

impl From<&str> for SerializedBytes<Utf8ContentFormat> {
    fn from(val: &str) -> Self {
        SerializedBytes::from(val.as_bytes().to_vec())
    }
}
