use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor, NotB64EncodedError};
use ciborium::{Value, value::Integer};
#[allow(unused_imports)]
use coset::{CborSerializable, ProtectedHeader, RegisteredLabel, iana::CoapContentFormat};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use crate::{
    CONTENT_TYPE_PADDED_CBOR, CoseEncrypt0Bytes, CryptoError, EncString, EncodingError, KeyIds,
    SerializedMessage, SymmetricCryptoKey, XChaCha20Poly1305Key,
    cose::{
        SAFE_CONTENT_NAMESPACE, SAFE_OBJECT_NAMESPACE, SafeObjectNamespace, XCHACHA20_POLY1305,
        extract_integer,
    },
    safe::DataEnvelopeNamespace,
    utils::pad_bytes,
    xchacha20,
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
    pub fn seal<Ids: KeyIds, T>(
        data: T,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<(Self, Ids::Symmetric), DataEnvelopeError>
    where
        T: Serialize + SealableVersionedData,
    {
        let (envelope, cek) = Self::seal_ref(&data, &T::NAMESPACE)?;
        let cek_id = ctx.generate_symmetric_key();
        ctx.set_symmetric_key_internal(cek_id, SymmetricCryptoKey::XChaCha20Poly1305Key(cek))
            .map_err(|_| DataEnvelopeError::KeyStoreError)?;
        Ok((envelope, cek_id))
    }

    /// Seals a struct into an encrypted blob. The content encryption key is wrapped with the
    /// provided wrapping key
    pub fn seal_with_wrapping_key<Ids: KeyIds, T>(
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
            .map_err(|_| DataEnvelopeError::EncryptionError)?;

        Ok((envelope, wrapped_cek))
    }

    /// Seals a struct into an encrypted blob, and returns the encrypted blob and the
    /// content-encryption-key.
    fn seal_ref<T>(
        data: &T,
        namespace: &DataEnvelopeNamespace,
    ) -> Result<(DataEnvelope, XChaCha20Poly1305Key), DataEnvelopeError>
    where
        T: Serialize + SealableVersionedData,
    {
        let mut cek = XChaCha20Poly1305Key::make();

        // Serialize the message
        let serialized_message =
            SerializedMessage::encode(&data).map_err(|_| DataEnvelopeError::EncodingError)?;
        if serialized_message.content_type() != coset::iana::CoapContentFormat::Cbor {
            return Err(DataEnvelopeError::UnsupportedContentFormat);
        }

        let serialized_and_padded_message = pad_cbor(serialized_message.as_bytes())
            .map_err(|_| DataEnvelopeError::EncodingError)?;

        // Build the COSE headers
        let mut protected_header = coset::HeaderBuilder::new()
            .key_id(cek.key_id.to_vec())
            .content_type(CONTENT_TYPE_PADDED_CBOR.to_string())
            .value(
                SAFE_OBJECT_NAMESPACE,
                Value::from(SafeObjectNamespace::DataEnvelope as i64),
            )
            .value(
                SAFE_CONTENT_NAMESPACE,
                ciborium::Value::Integer(Integer::from(namespace.as_i64())),
            )
            .build();
        protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));

        // Encrypt the message
        let mut nonce = [0u8; xchacha20::NONCE_SIZE];
        let encrypt0 = coset::CoseEncrypt0Builder::new()
            .protected(protected_header)
            .create_ciphertext(&serialized_and_padded_message, &[], |data, aad| {
                let ciphertext =
                    crate::xchacha20::encrypt_xchacha20_poly1305(&(*cek.enc_key).into(), data, aad);
                nonce = ciphertext.nonce();
                ciphertext.encrypted_bytes().to_vec()
            })
            .unprotected(coset::HeaderBuilder::new().iv(nonce.to_vec()).build())
            .build();

        // Serialize the COSE message
        let envelope_data = encrypt0
            .to_vec()
            .map(CoseEncrypt0Bytes::from)
            .map_err(|_| DataEnvelopeError::EncodingError)?;

        // Disable key operations other than decrypt on the CEK
        cek.disable_key_operation(coset::iana::KeyOperation::Encrypt)
            .disable_key_operation(coset::iana::KeyOperation::WrapKey)
            .disable_key_operation(coset::iana::KeyOperation::UnwrapKey);

        Ok((DataEnvelope { envelope_data }, cek))
    }

    /// Unseals the data from the encrypted blob using a content-encryption-key stored in the
    /// context.
    pub fn unseal<Ids: KeyIds, T>(
        &self,
        cek_keyslot: Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableVersionedData,
    {
        let cek = ctx
            .get_symmetric_key(cek_keyslot)
            .map_err(|_| DataEnvelopeError::KeyStoreError)?;

        match cek {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => self.unseal_ref(&T::NAMESPACE, key),
            _ => Err(DataEnvelopeError::UnsupportedContentFormat),
        }
    }

    /// Unseals the data from the encrypted blob and wrapped content-encryption-key.
    pub fn unseal_with_wrapping_key<Ids: KeyIds, T>(
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
            .map_err(|_| DataEnvelopeError::DecryptionError)?;
        self.unseal(cek, ctx)
    }

    /// Unseals the data from the encrypted blob using the provided content-encryption-key.
    fn unseal_ref<T>(
        &self,
        namespace: &DataEnvelopeNamespace,
        cek: &XChaCha20Poly1305Key,
    ) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableVersionedData,
    {
        // Parse the COSE message
        let msg = coset::CoseEncrypt0::from_slice(self.envelope_data.as_ref())
            .map_err(|_| DataEnvelopeError::CoseDecodingError)?;
        let envelope_namespace = extract_namespace(&msg.protected.header)?;
        let safe_object_namespace = extract_safe_object_namespace(&msg.protected.header)?;
        let content_format =
            content_format(&msg.protected).map_err(|_| DataEnvelopeError::DecodingError)?;

        // Validate the message
        if !matches!(
            msg.protected.header.alg,
            Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305)),
        ) {
            return Err(DataEnvelopeError::DecryptionError);
        }
        if msg.protected.header.key_id != cek.key_id {
            return Err(DataEnvelopeError::WrongKey);
        }

        if safe_object_namespace != SafeObjectNamespace::DataEnvelope as i64 {
            return Err(DataEnvelopeError::InvalidNamespace);
        }

        if envelope_namespace != *namespace {
            return Err(DataEnvelopeError::InvalidNamespace);
        }
        if content_format != CONTENT_TYPE_PADDED_CBOR {
            return Err(DataEnvelopeError::UnsupportedContentFormat);
        }

        // Decrypt the message
        let decrypted_message = msg
            .decrypt_ciphertext(
                &[],
                || CryptoError::MissingField("ciphertext"),
                |data, aad| {
                    let nonce = msg.unprotected.iv.as_slice();
                    crate::xchacha20::decrypt_xchacha20_poly1305(
                        nonce
                            .try_into()
                            .map_err(|_| CryptoError::InvalidNonceLength)?,
                        &(*cek.enc_key).into(),
                        data,
                        aad,
                    )
                },
            )
            .map_err(|_| DataEnvelopeError::DecryptionError)?;

        let unpadded_message =
            unpad_cbor(&decrypted_message).map_err(|_| DataEnvelopeError::DecryptionError)?;

        // Deserialize the message
        let serialized_message =
            SerializedMessage::from_bytes(unpadded_message, CoapContentFormat::Cbor);
        serialized_message
            .decode()
            .map_err(|_| DataEnvelopeError::DecodingError)
    }
}

/// Helper function to extract the namespace from a `ProtectedHeader`. The namespace is stored
/// as a custom header value using the DATA_ENVELOPE_NAMESPACE label.
fn extract_namespace(header: &coset::Header) -> Result<DataEnvelopeNamespace, DataEnvelopeError> {
    let namespace_value = header
        .rest
        .iter()
        .find(|(label, _)| {
            if let coset::Label::Int(label_int) = label {
                *label_int == SAFE_CONTENT_NAMESPACE
            } else {
                false
            }
        })
        .map(|(_, value)| value)
        .ok_or(DataEnvelopeError::InvalidNamespace)?;

    let namespace_int = match namespace_value {
        ciborium::Value::Integer(int) => {
            let int_val: i128 = (*int).into();
            int_val
        }
        _ => return Err(DataEnvelopeError::InvalidNamespace),
    };

    DataEnvelopeNamespace::try_from(namespace_int).map_err(|_| DataEnvelopeError::InvalidNamespace)
}

fn extract_safe_object_namespace(header: &coset::Header) -> Result<i64, DataEnvelopeError> {
    match extract_integer(header, SAFE_OBJECT_NAMESPACE, "safe object namespace") {
        Ok(value) => value.try_into().map_err(|_| {
            DataEnvelopeError::ParsingError("Invalid safe object namespace".to_string())
        }),
        Err(_) => Err(DataEnvelopeError::ParsingError(
            "Missing object namespace".to_string(),
        )),
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
        f.debug_struct("DataEnvelope")
            .field("envelope_data", &self.envelope_data)
            .finish()
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
    CoseDecodingError,
    /// Indicates that there was an error during decoding of the message.
    #[error("Failed to decode the content of the envelope")]
    DecodingError,
    /// Indicates that there was an error during encoding of the message.
    #[error("Encoding error")]
    EncodingError,
    /// Indicates that there was an error with the key store.
    #[error("KeyStore error")]
    KeyStoreError,
    /// Indicates that there was an error during decryption.
    #[error("Decryption error")]
    DecryptionError,
    /// Indicates that there was an error during encryption.
    #[error("Encryption error")]
    EncryptionError,
    /// Indicates that there was an error parsing the DataEnvelope.
    #[error("Parsing error: {0}")]
    ParsingError(String),
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

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::traits::tests::TestIds;

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

    const TEST_VECTOR_CEK: &str =
        "pQEEAlB5RTKA0xXdA7C4iQE4QfVUAzoAARFvBIEEIFggQYqnsrAfeFFTaXGXB54YrksB6eQcctMpnaZ8rG6rMJ0B";
    const TEST_VECTOR_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFB5RTKA0xXdA7C4iQE4QfVUOgABOIECOgABOIAgoQVYGLfQrYHVWxRxO6A8m/yp5DPbBIn3h8nijlhQj4jFwDLWfFz7le1Oy8dTls5vdEFg/FjjsPvXicI2bdb5KDdJCz/YkEu0kqjpQwdCcALpJLVJwgQQeKIeU2klBHEPZjnlLpRRXeCUp5c5BYQ=";

    #[test]
    #[ignore]
    fn generate_test_vectors() {
        let data: TestData = TestDataV1 { field: 123 }.into();
        let (envelope, cek) =
            DataEnvelope::seal_ref(&data, &DataEnvelopeNamespace::ExampleNamespace).unwrap();
        let unsealed_data: TestData = envelope
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace, &cek)
            .unwrap();
        assert_eq!(unsealed_data, data);
        println!(
            "const TEST_VECTOR_CEK: &str = \"{}\";",
            B64::from(SymmetricCryptoKey::XChaCha20Poly1305Key(cek).to_encoded())
        );
        println!(
            "const TEST_VECTOR_ENVELOPE: &str = \"{}\";",
            String::from(envelope)
        );
    }

    #[test]
    fn test_data_envelope_test_vector() {
        let cek = SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_CEK).unwrap()).unwrap();
        let cek = match cek {
            SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) => key.clone(),
            _ => panic!("Invalid CEK type"),
        };

        let envelope: DataEnvelope = TEST_VECTOR_ENVELOPE.parse().unwrap();
        let unsealed_data: TestData = envelope
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace, &cek)
            .unwrap();
        assert_eq!(unsealed_data, TestDataV1 { field: 123 }.into());
    }

    #[test]
    fn test_data_envelope() {
        // Create an instance of TestData
        let data: TestData = TestDataV1 { field: 42 }.into();

        // Seal the data
        let (envelope, cek) =
            DataEnvelope::seal_ref(&data, &DataEnvelopeNamespace::ExampleNamespace).unwrap();
        let unsealed_data: TestData = envelope
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace, &cek)
            .unwrap();

        // Verify that the unsealed data matches the original data
        assert_eq!(unsealed_data, data);
    }

    #[test]
    fn test_namespace_validation_success() {
        let data: TestData = TestDataV1 { field: 123 }.into();

        // Test with ExampleNamespace
        let (envelope1, cek1) =
            DataEnvelope::seal_ref(&data, &DataEnvelopeNamespace::ExampleNamespace).unwrap();
        let unsealed_data1: TestData = envelope1
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace, &cek1)
            .unwrap();
        assert_eq!(unsealed_data1, data);

        // Test with ExampleNamespace2
        let (envelope2, cek2) =
            DataEnvelope::seal_ref(&data, &DataEnvelopeNamespace::ExampleNamespace2).unwrap();
        let unsealed_data2: TestData = envelope2
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace2, &cek2)
            .unwrap();
        assert_eq!(unsealed_data2, data);
    }

    #[test]
    fn test_namespace_validation_failure() {
        let data: TestData = TestDataV1 { field: 456 }.into();

        // Seal with ExampleNamespace
        let (envelope, cek) =
            DataEnvelope::seal_ref(&data, &DataEnvelopeNamespace::ExampleNamespace).unwrap();

        // Try to unseal with wrong namespace - should fail
        let result: Result<TestData, DataEnvelopeError> =
            envelope.unseal_ref(&DataEnvelopeNamespace::ExampleNamespace2, &cek);
        assert!(matches!(result, Err(DataEnvelopeError::InvalidNamespace)));

        // Verify correct namespace still works
        let unsealed_data: TestData = envelope
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace, &cek)
            .unwrap();
        assert_eq!(unsealed_data, data);
    }

    #[test]
    fn test_namespace_validation_with_keystore() {
        let data: TestData = TestDataV1 { field: 789 }.into();
        let key_store = crate::store::KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        // Seal with keystore using ExampleNamespace2
        let (envelope, cek) =
            DataEnvelope::seal_ref(&data, &DataEnvelopeNamespace::ExampleNamespace2).unwrap();
        ctx.set_symmetric_key_internal(
            crate::traits::tests::TestSymmKey::A(0),
            SymmetricCryptoKey::XChaCha20Poly1305Key(cek),
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
        let (envelope1, cek1) =
            DataEnvelope::seal_ref(&data1, &DataEnvelopeNamespace::ExampleNamespace).unwrap();
        let (envelope2, cek2) =
            DataEnvelope::seal_ref(&data2, &DataEnvelopeNamespace::ExampleNamespace2).unwrap();

        // Verify each envelope only opens with its correct namespace
        let unsealed1: TestData = envelope1
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace, &cek1)
            .unwrap();
        assert_eq!(unsealed1, data1);

        let unsealed2: TestData = envelope2
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace2, &cek2)
            .unwrap();
        assert_eq!(unsealed2, data2);

        // Cross-unsealing should fail
        assert!(matches!(
            envelope1.unseal_ref::<TestData>(&DataEnvelopeNamespace::ExampleNamespace2, &cek1),
            Err(DataEnvelopeError::InvalidNamespace)
        ));
        assert!(matches!(
            envelope2.unseal_ref::<TestData>(&DataEnvelopeNamespace::ExampleNamespace, &cek2),
            Err(DataEnvelopeError::InvalidNamespace)
        ));
    }
}
