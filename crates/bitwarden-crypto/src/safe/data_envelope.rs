use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor, NotB64EncodedError};
#[allow(unused_imports)]
use coset::{CborSerializable, ProtectedHeader, RegisteredLabel, iana::CoapContentFormat};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use crate::{
    Aes256GcmKey, CONTENT_TYPE_PADDED_CBOR, CoseEncrypt0Bytes, CoseKeyView, CryptoError, EncString,
    EncodingError, KeyId, KeySlotIds, SerializedMessage, SymmetricCryptoKey,
    cose::{
        ContentNamespace, SafeObjectNamespace,
        symmetric::{
            CoseAlgorithmPolicy, CoseContentEncryptionAlgorithm, decrypt_cose0, encrypt_cose0,
        },
    },
    safe::{
        ContentEncryptionKey,
        helpers::{debug_fmt, set_safe_namespaces, validate_safe_namespaces},
    },
    utils::pad_bytes,
};

pub(crate) const DATA_ENVELOPE_PADDING_SIZE: usize = 64;

/// Marker trait for data that can be sealed in a `DataEnvelope`.
///
/// Do not manually implement this! Use the generate_versioned_sealable! macro instead.
pub trait SealableVersionedData: Serialize + DeserializeOwned {
    /// The namespace to use when sealing this type of data. This must be unique per struct.
    const NAMESPACE: DataEnvelopeNamespace;
}

/// Marker trait for data that can be sealed in a `DataEnvelope`.
///
/// Note: If you implement this trait, you agree to the following:
/// The struct serialization format is stable. Struct modifications must maintain backward
/// compatibility with existing serialized data. Changes that break deserialization are considered
/// breaking changes and require a new version and struct.
///
/// Ideally, when creating a new struct, create a test vector (a sealed DataEnvelope for a test
/// value), and create a unit test ensuring that it permanently deserializes correctly.
///
/// To make breaking changes, introduce a new version. This should use the
/// `generate_versioned_sealable!` macro to auto-generate the versioning code. Please see the
/// examples directory.
pub trait SealableData: Serialize + DeserializeOwned {}

/// `DataEnvelope` allows sealing structs entire structs to encrypted blobs.
///
/// Sealing a struct results in an encrypted blob, and a content-encryption-key. The
/// content-encryption-key must be provided again when unsealing the data. A content encryption key
/// allows easy key-rotation of the encrypting-key, as now just the content-encryption-keys need to
/// be re-uploaded, instead of all data.
///
/// The content-encryption-key cannot be re-used for encrypting other data.
///
/// Note: This is explicitly meant for structured data, not large binary blobs (files).
#[derive(Clone)]
pub struct DataEnvelope {
    envelope_data: CoseEncrypt0Bytes,
}

impl DataEnvelope {
    /// Seals a struct into an encrypted blob, and stores the content-encryption-key in the provided
    /// context.
    pub fn seal<Ids: KeySlotIds, T>(
        data: T,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<(Self, Ids::Symmetric), DataEnvelopeError>
    where
        T: Serialize + SealableVersionedData,
    {
        // The content-encryption-key is a fresh, single-use content-encryption-key (CEK) stored in
        // the context.
        let cek_id = ContentEncryptionKey::make(ctx);
        let mut cek = match ctx.get_symmetric_key(cek_id) {
            Ok(SymmetricCryptoKey::Aes256GcmKey(key)) => key.clone(),
            _ => return Err(DataEnvelopeError::KeyStore),
        };
        let envelope = Self::seal_ref(&data, T::NAMESPACE, &cek)?;

        // Restrict the CEK to decryption only before persisting it: once the data is sealed, the
        // CEK must never be used to encrypt, wrap, or unwrap again.
        cek.disable_key_operation(coset::iana::KeyOperation::Encrypt)
            .disable_key_operation(coset::iana::KeyOperation::WrapKey)
            .disable_key_operation(coset::iana::KeyOperation::UnwrapKey);
        ctx.set_symmetric_key_internal(cek_id, SymmetricCryptoKey::Aes256GcmKey(cek))
            .map_err(|_| DataEnvelopeError::KeyStore)?;
        Ok((envelope, cek_id))
    }

    /// Seals a struct into an encrypted blob. The content encryption key is wrapped with the
    /// provided wrapping key
    pub fn seal_with_wrapping_key<Ids: KeySlotIds, T>(
        data: T,
        wrapping_key: &Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<(Self, EncString), DataEnvelopeError>
    where
        T: Serialize + SealableVersionedData,
    {
        let (envelope, cek) = Self::seal(data, ctx)?;

        let wrapped_cek = ctx
            .wrap_symmetric_key(*wrapping_key, cek)
            .map_err(|_| DataEnvelopeError::Encryption)?;

        Ok((envelope, wrapped_cek))
    }

    /// Seals a struct into an encrypted blob using the provided content-encryption-key, and returns
    /// the encrypted blob.
    fn seal_ref<T>(
        data: &T,
        namespace: DataEnvelopeNamespace,
        cek: &Aes256GcmKey,
    ) -> Result<DataEnvelope, DataEnvelopeError>
    where
        T: Serialize + SealableVersionedData,
    {
        // Serialize the message
        let serialized_message =
            SerializedMessage::encode(&data).map_err(|_| DataEnvelopeError::Encoding)?;
        if serialized_message.content_type() != coset::iana::CoapContentFormat::Cbor {
            return Err(DataEnvelopeError::UnsupportedContentFormat);
        }

        let serialized_and_padded_message =
            pad_cbor(serialized_message.as_bytes()).map_err(|_| DataEnvelopeError::Encoding)?;

        // Build the COSE headers
        let mut protected_header = coset::HeaderBuilder::new()
            .key_id(cek.key_id.as_slice().to_vec())
            .content_type(CONTENT_TYPE_PADDED_CBOR.to_string())
            .build();
        set_safe_namespaces(
            &mut protected_header,
            SafeObjectNamespace::DataEnvelope,
            namespace,
        );

        // Encrypt the message. `encrypt_cose0` declares the content-encryption algorithm
        // (AES-256-GCM) in the protected header and stores a fresh nonce in the unprotected `iv`
        // header.
        let encrypt0 = encrypt_cose0(
            CoseContentEncryptionAlgorithm::Aes256Gcm,
            coset::CoseEncrypt0Builder::new(),
            protected_header,
            &serialized_and_padded_message,
            cek.enc_key.as_slice(),
        )
        .map_err(|_| DataEnvelopeError::Encoding)?;

        // Serialize the COSE message
        let envelope_data = encrypt0
            .to_vec()
            .map(CoseEncrypt0Bytes::from)
            .map_err(|_| DataEnvelopeError::Encoding)?;

        Ok(DataEnvelope { envelope_data })
    }

    /// Unseals the data from the encrypted blob using a content-encryption-key stored in the
    /// context.
    pub fn unseal<Ids: KeySlotIds, T>(
        &self,
        cek_keyslot: Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableVersionedData,
    {
        let cek = ctx
            .get_symmetric_key(cek_keyslot)
            .map_err(|_| DataEnvelopeError::KeyStore)?;

        // AES-256-GCM (current), XAES-256-GCM, and XChaCha20-Poly1305 (legacy)
        // content-encryption keys are accepted. The typed key's algorithm must match the algorithm
        // in the envelope's protected header.
        let view = cek
            .as_cose_key_view()
            .ok_or(DataEnvelopeError::UnsupportedContentFormat)?;
        self.unseal_ref(T::NAMESPACE, view)
    }

    /// Unseals the data from the encrypted blob and wrapped content-encryption-key.
    pub fn unseal_with_wrapping_key<Ids: KeySlotIds, T>(
        &self,
        wrapping_key: &Ids::Symmetric,
        wrapped_cek: &EncString,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableVersionedData,
    {
        let cek = ctx
            .unwrap_symmetric_key(*wrapping_key, wrapped_cek)
            .map_err(|_| DataEnvelopeError::Decryption)?;
        self.unseal(cek, ctx)
    }

    /// Unseals the data from the encrypted blob using the provided content-encryption-key, which
    /// may be an AES-256-GCM, XAES-256-GCM, or legacy XChaCha20-Poly1305 key.
    fn unseal_ref<T>(
        &self,
        namespace: DataEnvelopeNamespace,
        cek: CoseKeyView,
    ) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableVersionedData,
    {
        // Parse the COSE message
        let msg = coset::CoseEncrypt0::from_slice(self.envelope_data.as_ref())
            .map_err(|_| DataEnvelopeError::CoseDecoding)?;
        let content_format =
            content_format(&msg.protected).map_err(|_| DataEnvelopeError::Decoding)?;

        // Validate the message
        if msg.protected.header.key_id != cek.key_id().as_slice() {
            return Err(DataEnvelopeError::WrongKey);
        }

        validate_safe_namespaces(
            &msg.protected.header,
            SafeObjectNamespace::DataEnvelope,
            namespace,
        )
        .map_err(|_| DataEnvelopeError::InvalidNamespace)?;

        if content_format != CONTENT_TYPE_PADDED_CBOR {
            return Err(DataEnvelopeError::UnsupportedContentFormat);
        }

        // Bind the protected content-encryption algorithm to the independently typed CEK before
        // attempting decryption. DataEnvelope has no legacy format that omits the algorithm.
        let decrypted_message = decrypt_cose0(
            &msg,
            CoseAlgorithmPolicy::Exactly(cek.algorithm()),
            cek.key_bytes(),
        )
        .map_err(|_| DataEnvelopeError::Decryption)?;

        let unpadded_message =
            unpad_cbor(&decrypted_message).map_err(|_| DataEnvelopeError::Decryption)?;

        // Deserialize the message
        let serialized_message =
            SerializedMessage::from_bytes(unpadded_message, CoapContentFormat::Cbor);
        serialized_message
            .decode()
            .map_err(|_| DataEnvelopeError::Decoding)
    }
}

/// Helper function to extract the content type from a `ProtectedHeader`. The content type is a
/// standardized header set on the protected headers of the signature object. Currently we only
/// support registered values, but PrivateUse values are also allowed in the COSE specification.
pub(super) fn content_format(protected_header: &ProtectedHeader) -> Result<String, EncodingError> {
    protected_header
        .header
        .content_type
        .as_ref()
        .and_then(|ct| match ct {
            RegisteredLabel::Text(content_format) => Some(content_format.clone()),
            _ => None,
        })
        .ok_or(EncodingError::InvalidCoseEncoding)
}

impl From<&DataEnvelope> for Vec<u8> {
    fn from(val: &DataEnvelope) -> Self {
        val.envelope_data.to_vec()
    }
}

impl From<Vec<u8>> for DataEnvelope {
    fn from(data: Vec<u8>) -> Self {
        DataEnvelope {
            envelope_data: CoseEncrypt0Bytes::from(data),
        }
    }
}

impl std::fmt::Debug for DataEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("DataEnvelope");
        if let Ok(msg) = coset::CoseEncrypt0::from_slice(self.envelope_data.as_ref()) {
            debug_fmt::<DataEnvelopeNamespace>(&mut s, &msg.protected.header);
            if let Ok(encrypted_by) = KeyId::try_from(msg.protected.header.key_id.as_slice()) {
                s.field("encrypted_by", &encrypted_by);
            }
        }
        s.finish()
    }
}

impl FromStr for DataEnvelope {
    type Err = NotB64EncodedError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s)?;
        Ok(Self::from(data.into_bytes()))
    }
}

impl From<DataEnvelope> for String {
    fn from(val: DataEnvelope) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
    }
}

impl<'de> Deserialize<'de> for DataEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for DataEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized: Vec<u8> = self.into();
        serializer.serialize_str(&B64::from(serialized).to_string())
    }
}

impl std::fmt::Display for DataEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let serialized: Vec<u8> = self.into();
        write!(f, "{}", B64::from(serialized))
    }
}

/// Error type for `DataEnvelope` operations.
#[derive(Debug, Error)]
pub enum DataEnvelopeError {
    /// Indicates that the content format is not supported.
    #[error("Unsupported content format")]
    UnsupportedContentFormat,
    /// Indicates that there was an error during decoding of the message.
    #[error("Failed to decode COSE message")]
    CoseDecoding,
    /// Indicates that there was an error during decoding of the message.
    #[error("Failed to decode the content of the envelope")]
    Decoding,
    /// Indicates that there was an error during encoding of the message.
    #[error("Encoding error")]
    Encoding,
    /// Indicates that there was an error with the key store.
    #[error("KeyStore error")]
    KeyStore,
    /// Indicates that there was an error during decryption.
    #[error("Decryption error")]
    Decryption,
    /// Indicates that there was an error during encryption.
    #[error("Encryption error")]
    Encryption,
    /// Indicates that there was an error parsing the DataEnvelope.
    #[error("Parsing error: {0}")]
    Parsing(String),
    /// Indicates that the data envelope namespace is invalid.
    #[error("Invalid namespace")]
    InvalidNamespace,
    /// Indicates that the wrong key was used for decryption.
    #[error("Wrong key used for decryption")]
    WrongKey,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type DataEnvelope = Tagged<string, "DataEnvelope">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for DataEnvelope {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for DataEnvelope {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;

        let s = unsafe { String::from_abi(abi) };
        Self::from_str(&s).unwrap_throw()
    }
}

fn pad_cbor(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut data = data.to_vec();
    pad_bytes(&mut data, DATA_ENVELOPE_PADDING_SIZE).map_err(|_| CryptoError::InvalidPadding)?;
    Ok(data)
}

fn unpad_cbor(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let unpadded = crate::utils::unpad_bytes(data).map_err(|_| CryptoError::InvalidPadding)?;
    Ok(unpadded.to_vec())
}

/// Generates a versioned enum that implements `SealableData`.
///
/// This serializes to an adjacently tagged enum, with the "version" field being set to the provided
/// version, and the "content" field being the serialized struct.
///
///
/// ```
/// use bitwarden_crypto::{safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData}, generate_versioned_sealable};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// struct MyItemV1 {
///     a: u32,
///     b: String,
/// }
/// impl SealableData for MyItemV1 {}
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// struct MyItemV2 {
///     a: u32,
///     b: bool,
///     c: bool,
/// }
/// impl SealableData for MyItemV2 {}
///
/// generate_versioned_sealable!(
///     MyItem,
///     DataEnvelopeNamespace::VaultItem,
///     [
///         MyItemV1 => "1",
///         MyItemV2 => "2",
///     ]
/// );
/// ```
#[macro_export]
macro_rules! generate_versioned_sealable {
    (
        // Provide the name
        $enum_name:ident,
        // Provide the namespace
        $namespace:path,
        // Provide mappings from the variant to version. This must not be changed later.
        [ $( $variant_ty:ident => $rename:literal ),+ $(,)? ]
    ) => {
        // Implement the enum
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        #[serde(tag = "version", content = "content")]
        enum $enum_name {
            $(
                #[serde(rename = $rename)]
                // Strip the `MyItem` prefix from type name if you want shorter variant names
                $variant_ty($variant_ty),
            )+
        }

        // Implement the SealableVersionedData trait for the enum
        impl SealableVersionedData for $enum_name
        where
            $( $variant_ty: SealableData ),+
        {
            // Implement with the specified namespace
            const NAMESPACE: DataEnvelopeNamespace = $namespace;
        }

        // Implement Into from each variant to the enum
        $(
            impl From<$variant_ty> for $enum_name {
                fn from(value: $variant_ty) -> Self {
                    Self::$variant_ty(value)
                }
            }
        )+
    };
}

/// Data envelopes are domain-separated within bitwarden, to prevent cross protocol attacks.
///
/// A new struct shall use a new data envelope namespace. Generally, this means
/// that a data envelope namespace has exactly one associated valid message struct. Internal
/// versioning within a namespace is permitted and up to the domain owner to ensure is done
/// correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataEnvelopeNamespace {
    /// The namespace for vault items ("ciphers")
    VaultItem = 1,
    /// The namespace for organization member invite data (the organization public-key thumbprint
    /// and the invite secret), sealed with the invite key.
    OrganizationInvite = 2,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace = -1,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace2 = -2,
}

impl DataEnvelopeNamespace {
    /// Returns the numeric value of the namespace.
    fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl TryFrom<i128> for DataEnvelopeNamespace {
    type Error = DataEnvelopeError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DataEnvelopeNamespace::VaultItem),
            2 => Ok(DataEnvelopeNamespace::OrganizationInvite),
            #[cfg(test)]
            -1 => Ok(DataEnvelopeNamespace::ExampleNamespace),
            #[cfg(test)]
            -2 => Ok(DataEnvelopeNamespace::ExampleNamespace2),
            _ => Err(DataEnvelopeError::InvalidNamespace),
        }
    }
}

impl TryFrom<i64> for DataEnvelopeNamespace {
    type Error = DataEnvelopeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::try_from(i128::from(value))
    }
}

impl From<DataEnvelopeNamespace> for i128 {
    fn from(val: DataEnvelopeNamespace) -> Self {
        val.as_i64().into()
    }
}

impl ContentNamespace for DataEnvelopeNamespace {}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::{SymmetricKeyAlgorithm, safe::KeyEncryptionKey, traits::tests::TestIds};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestDataV1 {
        field: u32,
    }
    impl SealableData for TestDataV1 {}

    generate_versioned_sealable!(
        TestData,
        DataEnvelopeNamespace::ExampleNamespace,
        [
            TestDataV1 => "1",
        ]
    );

    /// Legacy XChaCha20-Poly1305 test vector, kept to prove that DataEnvelopes sealed before the
    /// switch to AES-256-GCM still decrypt (the algorithm is recovered from the protected header).
    const TEST_VECTOR_CEK: &str =
        "pQEEAlB5RTKA0xXdA7C4iQE4QfVUAzoAARFvBIEEIFggQYqnsrAfeFFTaXGXB54YrksB6eQcctMpnaZ8rG6rMJ0B";
    const TEST_VECTOR_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFB5RTKA0xXdA7C4iQE4QfVUOgABOIECOgABOIAgoQVYGLfQrYHVWxRxO6A8m/yp5DPbBIn3h8nijlhQj4jFwDLWfFz7le1Oy8dTls5vdEFg/FjjsPvXicI2bdb5KDdJCz/YkEu0kqjpQwdCcALpJLVJwgQQeKIeU2klBHEPZjnlLpRRXeCUp5c5BYQ=";

    /// AES-256-GCM test vector, generated by `generate_aes_gcm_test_vectors`. Locks the current
    /// (FIPS-compatible) DataEnvelope wire format for backward compatibility.
    const TEST_VECTOR_AES_GCM_CEK: &str =
        "pQEEAlDLIx+izSLk9h9sVjHFzpKoAwMEgQQgWCDWM3iwTX2/LHTIaXS0cPIKCYFZethtKyD6Pucdt4fkGQQEBAQ=";
    const TEST_VECTOR_AES_GCM_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUMsjH6LNIuT2H2xWMcXOkqg6AAE4gQI6AAE4gCChBUyoF/oGEm+lJYrjjgdYUGIH5LnQjqFMWo2BJORVPYH2+hEWkxIn3tRgAMHNwIr0nTXMVD1EyVGZOsHSDMPqn2HaYrDeR5s+Rg0ezZ2WLh8n2FbdC44A/ExOms4IHcyT";

    /// Test helper: unseal an envelope with an AES-256-GCM content-encryption key.
    fn unseal_with_cek<T>(
        envelope: &DataEnvelope,
        namespace: DataEnvelopeNamespace,
        cek: &Aes256GcmKey,
    ) -> Result<T, DataEnvelopeError>
    where
        T: serde::de::DeserializeOwned + SealableVersionedData,
    {
        envelope.unseal_ref(namespace, CoseKeyView::Aes256Gcm(cek))
    }

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let data: TestData = TestDataV1 { field: 42 }.into();
        let envelope = DataEnvelope::seal_ref(
            &data,
            DataEnvelopeNamespace::ExampleNamespace,
            &Aes256GcmKey::make(),
        )
        .unwrap();
        println!("{:?}", envelope);
    }

    #[test]
    #[ignore]
    fn generate_aes_gcm_test_vectors() {
        let data: TestData = TestDataV1 { field: 123 }.into();
        let cek = Aes256GcmKey::make();
        let envelope =
            DataEnvelope::seal_ref(&data, DataEnvelopeNamespace::ExampleNamespace, &cek).unwrap();
        let unsealed_data: TestData =
            unseal_with_cek(&envelope, DataEnvelopeNamespace::ExampleNamespace, &cek).unwrap();
        assert_eq!(unsealed_data, data);
        println!(
            "const TEST_VECTOR_AES_GCM_CEK: &str = \"{}\";",
            B64::from(SymmetricCryptoKey::Aes256GcmKey(cek).to_encoded())
        );
        println!(
            "const TEST_VECTOR_AES_GCM_ENVELOPE: &str = \"{}\";",
            String::from(envelope)
        );
    }

    #[test]
    fn test_data_envelope_legacy_xchacha20_test_vector() {
        let cek = SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_CEK).unwrap()).unwrap();
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref cek) = cek else {
            panic!("Invalid CEK type");
        };

        let envelope: DataEnvelope = TEST_VECTOR_ENVELOPE.parse().unwrap();
        let unsealed_data: TestData = envelope
            .unseal_ref(
                DataEnvelopeNamespace::ExampleNamespace,
                CoseKeyView::XChaCha20Poly1305(cek),
            )
            .unwrap();
        assert_eq!(unsealed_data, TestDataV1 { field: 123 }.into());
    }

    #[test]
    fn test_data_envelope_aes_gcm_test_vector() {
        let cek =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_AES_GCM_CEK).unwrap()).unwrap();
        let SymmetricCryptoKey::Aes256GcmKey(ref cek) = cek else {
            panic!("Invalid CEK type");
        };

        let envelope: DataEnvelope = TEST_VECTOR_AES_GCM_ENVELOPE.parse().unwrap();
        let unsealed_data: TestData =
            unseal_with_cek(&envelope, DataEnvelopeNamespace::ExampleNamespace, cek).unwrap();
        assert_eq!(unsealed_data, TestDataV1 { field: 123 }.into());
    }

    #[test]
    fn test_data_envelope_uses_aes_gcm() {
        let data: TestData = TestDataV1 { field: 42 }.into();
        let envelope = DataEnvelope::seal_ref(
            &data,
            DataEnvelopeNamespace::ExampleNamespace,
            &Aes256GcmKey::make(),
        )
        .unwrap();

        // New envelopes declare AES-256-GCM in their protected header.
        let msg = coset::CoseEncrypt0::from_slice(envelope.envelope_data.as_ref()).unwrap();
        assert_eq!(
            msg.protected.header.alg,
            Some(coset::Algorithm::Assigned(coset::iana::Algorithm::A256GCM))
        );
    }

    #[test]
    fn test_data_envelope() {
        // Create an instance of TestData
        let data: TestData = TestDataV1 { field: 42 }.into();

        // Seal the data
        let cek = Aes256GcmKey::make();
        let envelope =
            DataEnvelope::seal_ref(&data, DataEnvelopeNamespace::ExampleNamespace, &cek).unwrap();
        let unsealed_data: TestData =
            unseal_with_cek(&envelope, DataEnvelopeNamespace::ExampleNamespace, &cek).unwrap();

        // Verify that the unsealed data matches the original data
        assert_eq!(unsealed_data, data);
    }

    #[test]
    fn test_data_envelope_with_keystore_roundtrip() {
        let data: TestData = TestDataV1 { field: 7 }.into();
        let key_store = crate::store::KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let (envelope, cek_id) = DataEnvelope::seal(data, &mut ctx).unwrap();

        // The CEK stored in the key store is an AES-256-GCM key.
        assert_eq!(
            ctx.get_symmetric_key_algorithm(cek_id).unwrap(),
            SymmetricKeyAlgorithm::Aes256Gcm
        );

        let unsealed: TestData = envelope.unseal(cek_id, &mut ctx).unwrap();
        assert_eq!(unsealed, TestDataV1 { field: 7 }.into());
    }

    #[test]
    fn test_data_envelope_wrapping_key_roundtrip() {
        let data: TestData = TestDataV1 { field: 99 }.into();
        let key_store = crate::store::KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let wrapping_key = KeyEncryptionKey::make(&mut ctx);

        let (envelope, wrapped_cek) =
            DataEnvelope::seal_with_wrapping_key(data, &wrapping_key, &mut ctx).unwrap();
        let unsealed: TestData = envelope
            .unseal_with_wrapping_key(&wrapping_key, &wrapped_cek, &mut ctx)
            .unwrap();
        assert_eq!(unsealed, TestDataV1 { field: 99 }.into());
    }

    #[test]
    fn test_namespace_validation_success() {
        let data: TestData = TestDataV1 { field: 123 }.into();

        // Test with ExampleNamespace
        let cek1 = Aes256GcmKey::make();
        let envelope1 =
            DataEnvelope::seal_ref(&data, DataEnvelopeNamespace::ExampleNamespace, &cek1).unwrap();
        let unsealed_data1: TestData =
            unseal_with_cek(&envelope1, DataEnvelopeNamespace::ExampleNamespace, &cek1).unwrap();
        assert_eq!(unsealed_data1, data);

        // Test with ExampleNamespace2
        let cek2 = Aes256GcmKey::make();
        let envelope2 =
            DataEnvelope::seal_ref(&data, DataEnvelopeNamespace::ExampleNamespace2, &cek2).unwrap();
        let unsealed_data2: TestData =
            unseal_with_cek(&envelope2, DataEnvelopeNamespace::ExampleNamespace2, &cek2).unwrap();
        assert_eq!(unsealed_data2, data);
    }

    #[test]
    fn test_namespace_validation_failure() {
        let data: TestData = TestDataV1 { field: 456 }.into();

        // Seal with ExampleNamespace
        let cek = Aes256GcmKey::make();
        let envelope =
            DataEnvelope::seal_ref(&data, DataEnvelopeNamespace::ExampleNamespace, &cek).unwrap();

        // Try to unseal with wrong namespace - should fail
        let result: Result<TestData, DataEnvelopeError> =
            unseal_with_cek(&envelope, DataEnvelopeNamespace::ExampleNamespace2, &cek);
        assert!(matches!(result, Err(DataEnvelopeError::InvalidNamespace)));

        // Verify correct namespace still works
        let unsealed_data: TestData =
            unseal_with_cek(&envelope, DataEnvelopeNamespace::ExampleNamespace, &cek).unwrap();
        assert_eq!(unsealed_data, data);
    }

    #[test]
    fn test_namespace_validation_with_keystore() {
        let data: TestData = TestDataV1 { field: 789 }.into();
        let key_store = crate::store::KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        // Seal with keystore using ExampleNamespace2
        let cek = Aes256GcmKey::make();
        let envelope =
            DataEnvelope::seal_ref(&data, DataEnvelopeNamespace::ExampleNamespace2, &cek).unwrap();
        ctx.set_symmetric_key_internal(
            crate::traits::tests::TestSymmKey::A(0),
            SymmetricCryptoKey::Aes256GcmKey(cek),
        )
        .unwrap();

        // Try to unseal with wrong namespace - should fail
        let result: Result<TestData, DataEnvelopeError> =
            envelope.unseal(crate::traits::tests::TestSymmKey::A(0), &mut ctx);
        assert!(matches!(result, Err(DataEnvelopeError::InvalidNamespace)));
    }

    #[test]
    fn test_namespace_cross_contamination_protection() {
        let data1: TestData = TestDataV1 { field: 111 }.into();
        let data2: TestData = TestDataV1 { field: 222 }.into();

        // Seal two different pieces of data with different namespaces
        let cek1 = Aes256GcmKey::make();
        let envelope1 =
            DataEnvelope::seal_ref(&data1, DataEnvelopeNamespace::ExampleNamespace, &cek1).unwrap();
        let cek2 = Aes256GcmKey::make();
        let envelope2 =
            DataEnvelope::seal_ref(&data2, DataEnvelopeNamespace::ExampleNamespace2, &cek2)
                .unwrap();

        // Verify each envelope only opens with its correct namespace
        let unsealed1: TestData =
            unseal_with_cek(&envelope1, DataEnvelopeNamespace::ExampleNamespace, &cek1).unwrap();
        assert_eq!(unsealed1, data1);

        let unsealed2: TestData =
            unseal_with_cek(&envelope2, DataEnvelopeNamespace::ExampleNamespace2, &cek2).unwrap();
        assert_eq!(unsealed2, data2);

        // Cross-unsealing should fail
        assert!(matches!(
            unseal_with_cek::<TestData>(
                &envelope1,
                DataEnvelopeNamespace::ExampleNamespace2,
                &cek1
            ),
            Err(DataEnvelopeError::InvalidNamespace)
        ));
        assert!(matches!(
            unseal_with_cek::<TestData>(&envelope2, DataEnvelopeNamespace::ExampleNamespace, &cek2),
            Err(DataEnvelopeError::InvalidNamespace)
        ));
    }
}
