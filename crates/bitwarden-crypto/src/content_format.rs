use bitwarden_encoding::B64;
use serde::{Deserialize, Serialize};

use crate::{
    CryptoError, EncString, KeyEncryptable, KeyEncryptableWithContentType, KeyIds, KeyStoreContext,
    PrimitiveEncryptable, SymmetricCryptoKey, traits::PrimitiveEncryptableWithContentType,
};

/// The content format describes the format of the contained bytes. Message encryption always
/// happens on the byte level, and this allows determining what format the contained data has. For
/// instance, an `EncString` in most cases contains UTF-8 encoded text. In some cases it may contain
/// a Pkcs8 private key, or a COSE key. Specifically, for COSE keys, this allows distinguishing
/// between the old symmetric key format, represented as `ContentFormat::OctetStream`, and the new
/// COSE key format, represented as `ContentFormat::CoseKey`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum ContentFormat {
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
}

mod private {
    /// This trait is used to seal the `ConstContentFormat` trait, preventing external
    /// implementations.
    pub trait Sealed {}
}

/// This trait is used to instantiate different typed byte vectors with a specific content format,
/// using `SerializedBytes<C>`. This allows for compile-time guarantees about the content format
/// of the serialized bytes. The exception here is the escape hatch using e.g. `from(Vec<u8>)`,
/// which can still be mis-used, but has to be misused explicitly.
pub trait ConstContentFormat: private::Sealed {
    /// Returns the content format as a `ContentFormat` enum.
    #[allow(private_interfaces)]
    fn content_format() -> ContentFormat;
}

/// A serialized byte array with a specific content format. This is used to represent data that has
/// a specific format, such as UTF-8 encoded text, raw bytes, or COSE keys. The content
/// format is used to determine how the bytes should be interpreted when encrypting or decrypting
/// the data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bytes<C: ConstContentFormat> {
    inner: Vec<u8>,
    _marker: std::marker::PhantomData<C>,
}

impl<C: ConstContentFormat> From<Vec<u8>> for Bytes<C> {
    fn from(inner: Vec<u8>) -> Self {
        Self {
            inner,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C: ConstContentFormat> From<&[u8]> for Bytes<C> {
    fn from(inner: &[u8]) -> Self {
        Self::from(inner.to_vec())
    }
}

impl<C: ConstContentFormat + FromB64ContentFormat> From<&B64> for Bytes<C> {
    fn from(val: &B64) -> Self {
        Self::from(val.as_bytes())
    }
}

impl<C: ConstContentFormat + FromB64ContentFormat> From<Bytes<C>> for B64 {
    fn from(val: Bytes<C>) -> Self {
        B64::from(val.as_ref())
    }
}

impl<C: ConstContentFormat> AsRef<[u8]> for Bytes<C> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl<C: ConstContentFormat> Bytes<C> {
    /// Returns the serialized bytes as a `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.inner.clone()
    }
}

/// Content format for UTF-8 encoded text. Used for most text messages.
#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) struct Utf8ContentFormat;
impl private::Sealed for Utf8ContentFormat {}
impl ConstContentFormat for Utf8ContentFormat {
    fn content_format() -> ContentFormat {
        ContentFormat::Utf8
    }
}
/// Utf8Bytes is a type alias for Bytes with `Utf8ContentFormat`, which is used for any textual
/// data.
pub(crate) type Utf8Bytes = Bytes<Utf8ContentFormat>;

/// Content format for raw bytes. Used for attachments and send seed keys.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct OctetStreamContentFormat;
impl private::Sealed for OctetStreamContentFormat {}
impl ConstContentFormat for OctetStreamContentFormat {
    #[allow(private_interfaces)]
    fn content_format() -> ContentFormat {
        ContentFormat::OctetStream
    }
}
/// OctetStreamBytes is a type alias for Bytes with `OctetStreamContentFormat`. This should be used
/// for e.g. attachments and other data without an explicit content format.
pub type OctetStreamBytes = Bytes<OctetStreamContentFormat>;

/// Content format for PKCS8 private keys in DER format.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Pkcs8PrivateKeyDerContentFormat;
impl private::Sealed for Pkcs8PrivateKeyDerContentFormat {}
impl ConstContentFormat for Pkcs8PrivateKeyDerContentFormat {
    #[allow(private_interfaces)]
    fn content_format() -> ContentFormat {
        ContentFormat::Pkcs8PrivateKey
    }
}
/// Pkcs8PrivateKeyBytes is a type alias for Bytes with `Pkcs8PrivateKeyDerContentFormat`. This is
/// used for PKCS8 private keys in DER format.
pub type Pkcs8PrivateKeyBytes = Bytes<Pkcs8PrivateKeyDerContentFormat>;

/// Content format for SPKI public keys in DER format.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SpkiPublicKeyDerContentFormat;
impl private::Sealed for SpkiPublicKeyDerContentFormat {}
impl ConstContentFormat for SpkiPublicKeyDerContentFormat {
    #[allow(private_interfaces)]
    fn content_format() -> ContentFormat {
        ContentFormat::SPKIPublicKeyDer
    }
}
impl FromB64ContentFormat for SpkiPublicKeyDerContentFormat {}
/// SpkiPublicKeyBytes is a type alias for Bytes with `SpkiPublicKeyDerContentFormat`. This is used
/// for SPKI public keys in DER format.
pub type SpkiPublicKeyBytes = Bytes<SpkiPublicKeyDerContentFormat>;

/// A marker trait for COSE content formats.
pub trait CoseContentFormat {}

/// A marker trait for content formats that can be converted from B64.
pub trait FromB64ContentFormat {}

/// Content format for COSE keys.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CoseKeyContentFormat;
impl private::Sealed for CoseKeyContentFormat {}
impl ConstContentFormat for CoseKeyContentFormat {
    #[allow(private_interfaces)]
    fn content_format() -> ContentFormat {
        ContentFormat::CoseKey
    }
}
impl CoseContentFormat for CoseKeyContentFormat {}
impl FromB64ContentFormat for CoseKeyContentFormat {}
/// CoseKeyBytes is a type alias for Bytes with `CoseKeyContentFormat`. This is used for serialized
/// CoseKey objects.
pub type CoseKeyBytes = Bytes<CoseKeyContentFormat>;

/// A legacy content format for Bitwarden keys. See `ContentFormat::BitwardenLegacyKey`
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BitwardenLegacyKeyContentFormat;
impl private::Sealed for BitwardenLegacyKeyContentFormat {}
impl ConstContentFormat for BitwardenLegacyKeyContentFormat {
    #[allow(private_interfaces)]
    fn content_format() -> ContentFormat {
        ContentFormat::BitwardenLegacyKey
    }
}
impl FromB64ContentFormat for BitwardenLegacyKeyContentFormat {}
/// BitwardenLegacyKeyBytes is a type alias for Bytes with `BitwardenLegacyKeyContentFormat`. This
/// is used for the legacy format for symmetric keys. A description of the format is available in
/// the `ContentFormat::BitwardenLegacyKey` documentation.
pub type BitwardenLegacyKeyBytes = Bytes<BitwardenLegacyKeyContentFormat>;

/// Content format for COSE Sign1 messages.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CoseSign1ContentFormat;
impl private::Sealed for CoseSign1ContentFormat {}
impl ConstContentFormat for CoseSign1ContentFormat {
    #[allow(private_interfaces)]
    fn content_format() -> ContentFormat {
        ContentFormat::CoseSign1
    }
}
impl CoseContentFormat for CoseSign1ContentFormat {}
impl FromB64ContentFormat for CoseSign1ContentFormat {}
/// CoseSign1Bytes is a type alias for Bytes with `CoseSign1ContentFormat`. This is used for
/// serialized COSE Sign1 messages.
pub type CoseSign1Bytes = Bytes<CoseSign1ContentFormat>;

impl<Ids: KeyIds, T: ConstContentFormat> PrimitiveEncryptable<Ids, Ids::Symmetric, EncString>
    for Bytes<T>
{
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<Ids>,
        key: Ids::Symmetric,
    ) -> Result<EncString, CryptoError> {
        self.inner.encrypt(ctx, key, T::content_format())
    }
}

impl<T: ConstContentFormat> KeyEncryptable<SymmetricCryptoKey, EncString> for &Bytes<T> {
    fn encrypt_with_key(self, key: &SymmetricCryptoKey) -> Result<EncString, CryptoError> {
        self.as_ref().encrypt_with_key(key, T::content_format())
    }
}

impl From<String> for Bytes<Utf8ContentFormat> {
    fn from(val: String) -> Self {
        Bytes::from(val.into_bytes())
    }
}

impl From<&str> for Bytes<Utf8ContentFormat> {
    fn from(val: &str) -> Self {
        Bytes::from(val.as_bytes().to_vec())
    }
}
