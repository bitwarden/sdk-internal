use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use ciborium::value::Integer;
#[allow(unused_imports)]
use coset::{CborSerializable, ProtectedHeader, RegisteredLabel, iana::CoapContentFormat};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use crate::{
    CoseEncrypt0Bytes, CryptoError, KeyIds, SerializedMessage, SymmetricCryptoKey,
    XChaCha20Poly1305Key,
    cose::{DATA_ENVELOPE_NAMESPACE, XCHACHA20_POLY1305},
    ensure_equal, ensure_matches,
    safe::DataEnvelopeNamespace,
    xchacha20,
};

/// Marker trait for data that can be sealed in a `DataEnvelope`.
pub trait SealableData: Serialize + Deserialize {
    /// The namespace to use when sealing this type of data. This must be unique per struct.
    const NAMESPACE: DataEnvelopeNamespace;
}

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
pub struct DataEnvelope {
    envelope_data: CoseEncrypt0Bytes,
}

impl Clone for DataEnvelope {
    fn clone(&self) -> Self {
        DataEnvelope {
            envelope_data: self.envelope_data.clone(),
        }
    }
}

impl DataEnvelope {
    /// Seals a struct into an encrypted blob, and stores the content-encryption-key in the provided
    /// context.
    pub fn seal<Ids: KeyIds, T>(
        data: T,
        cek_keyslot: Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<Self, DataEnvelopeError>
    where
        T: Serialize + SealableData,
    {
        let (envelope, cek) = Self::seal_ref(&data, &T::NAMESPACE)?;
        ctx.set_symmetric_key_internal(cek_keyslot, SymmetricCryptoKey::XChaCha20Poly1305Key(cek))
            .map_err(|_| DataEnvelopeError::KeyStoreError)?;
        Ok(envelope)
    }

    /// Seals a struct into an encrypted blob, and returns the encrypted blob and the
    /// content-encryption-key.
    fn seal_ref<T>(
        data: &T,
        namespace: &DataEnvelopeNamespace,
    ) -> Result<(DataEnvelope, XChaCha20Poly1305Key), DataEnvelopeError>
    where
        T: Serialize + SealableData,
    {
        let mut cek = XChaCha20Poly1305Key::make();

        // Serialize the message
        let serialized_message =
            SerializedMessage::encode(&data).map_err(|_| DataEnvelopeError::EncodingError)?;

        // Build the COSE headers
        let mut protected_header = coset::HeaderBuilder::new()
            .key_id(cek.key_id.to_vec())
            .content_format(serialized_message.content_type())
            .value(
                DATA_ENVELOPE_NAMESPACE,
                ciborium::Value::Integer(Integer::from(namespace.as_i64())),
            )
            .build();
        protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));

        // Encrypt the message
        let mut nonce = [0u8; xchacha20::NONCE_SIZE];
        let encrypt0 = coset::CoseEncrypt0Builder::new()
            .protected(protected_header)
            .create_ciphertext(serialized_message.as_bytes(), &[], |data, aad| {
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

        Ok((DataEnvelope { envelope_data }, cek.clone()))
    }

    /// Unseals the data from the encrypted blob using a content-encryption-key stored in the
    /// context.
    pub fn unseal<Ids: KeyIds, T>(
        &self,
        namespace: &DataEnvelopeNamespace,
        cek_keyslot: Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableData,
    {
        let cek = ctx
            .get_symmetric_key(cek_keyslot)
            .map_err(|_| DataEnvelopeError::KeyStoreError)?;

        match cek {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => self.unseal_ref(namespace, key),
            _ => Err(DataEnvelopeError::UnsupportedContentFormat),
        }
    }

    /// Unseals the data from the encrypted blob using the provided content-encryption-key.
    fn unseal_ref<T>(
        &self,
        namespace: &DataEnvelopeNamespace,
        cek: &XChaCha20Poly1305Key,
    ) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableData,
    {
        // Parse the COSE message
        let msg = coset::CoseEncrypt0::from_slice(self.envelope_data.as_ref())
            .map_err(|_| DataEnvelopeError::CoseDecodingError)?;
        let envelope_namespace = extract_namespace(&msg.protected.header)?;
        let content_type =
            content_type(&msg.protected).map_err(|_| DataEnvelopeError::DecodingError)?;

        // Validate the message
        ensure_matches!(msg.protected.header.alg, Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305)) => DataEnvelopeError::DecryptionError);
        ensure_equal!(msg.protected.header.key_id, cek.key_id => DataEnvelopeError::WrongKey);
        ensure_equal!(envelope_namespace, *namespace => DataEnvelopeError::InvalidNamespace);

        // Decrypt the message
        let decrypted_message = msg
            .decrypt(&[], |data, aad| {
                let nonce = msg.unprotected.iv.as_slice();
                crate::xchacha20::decrypt_xchacha20_poly1305(
                    nonce
                        .try_into()
                        .map_err(|_| DataEnvelopeError::DecryptionError)?,
                    &(*cek.enc_key).into(),
                    data,
                    aad,
                )
            })
            .map_err(|_| DataEnvelopeError::DecryptionError)?;

        // Deserialize the message
        let serialized_message = SerializedMessage::from_bytes(decrypted_message, content_type);
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
                *label_int == DATA_ENVELOPE_NAMESPACE
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

/// Helper function to extract the content type from a `ProtectedHeader`. The content type is a
/// standardized header set on the protected headers of the signature object. Currently we only
/// support registered values, but PrivateUse values are also allowed in the COSE specification.
pub(super) fn content_type(
    protected_header: &ProtectedHeader,
) -> Result<coset::iana::CoapContentFormat, CryptoError> {
    protected_header
        .header
        .content_type
        .as_ref()
        .and_then(|ct| match ct {
            RegisteredLabel::Assigned(content_format) => Some(*content_format),
            _ => None,
        })
        .ok_or_else(|| DataEnvelopeError::DecryptionError.into())
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
    type Err = DataEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| {
            DataEnvelopeError::ParsingError("Invalid DataEnvelope Base64 encoding".to_string())
        })?;
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
        let s = unsafe { String::from_abi(abi) };
        Self::from_str(&s).expect("Invalid DataEnvelope")
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::traits::tests::TestIds;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestData {
        field2: u32,
    }
    impl SealableData for TestData {
        const NAMESPACE: DataEnvelopeNamespace = DataEnvelopeNamespace::ExampleNamespace;
    }

    const TEST_VECTOR_CEK: &str =
        "pQEEAlDI6siwJ+XRw5/Dqb0imZkmAzoAARFvBIEEIFgg/LZGMeNOnBi/cMyAbeaZL9hN3owKxTHOYvbIAuwSdeIB";
    const TEST_VECTOR_ENVELOPE: &str = "g1gipAE6AAERbwMYPARQyOrIsCfl0cOfw6m9IpmZJjoAATiAIKEFWBi9F7Vx3IqByTEOsDOjXkSZZ0fCRueolG5YGkGeh20fm9wGww2LovW2QQXFt3UfFCUv2oCI";

    #[test]
    #[ignore]
    fn generate_test_vectors() {
        let data = TestData { field2: 123 };
        let (envelope, cek) =
            DataEnvelope::seal_ref(&data, &DataEnvelopeNamespace::ExampleNamespace).unwrap();
        let unsealed_data: TestData = envelope
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace, &cek)
            .unwrap();
        assert_eq!(unsealed_data, data);
        println!(
            "CEK: {}",
            B64::from(SymmetricCryptoKey::XChaCha20Poly1305Key(cek).to_encoded())
        );
        println!("Envelope: {}", String::from(envelope));
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
        assert_eq!(unsealed_data, TestData { field2: 123 });
    }

    #[test]
    fn test_data_envelope() {
        // Create an instance of TestData
        let data = TestData { field2: 42 };

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
        let data = TestData { field2: 123 };

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
        let data = TestData { field2: 456 };

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
        let data = TestData { field2: 789 };
        let key_store = crate::store::KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        // Seal with keystore using ExampleNamespace
        let envelope =
            DataEnvelope::seal(data, crate::traits::tests::TestSymmKey::A(0), &mut ctx).unwrap();

        // Try to unseal with wrong namespace - should fail
        let result: Result<TestData, DataEnvelopeError> = envelope.unseal(
            &DataEnvelopeNamespace::ExampleNamespace2,
            crate::traits::tests::TestSymmKey::A(0),
            &mut ctx,
        );
        assert!(matches!(result, Err(DataEnvelopeError::InvalidNamespace)));

        // Unseal with correct namespace - should succeed
        let unsealed_data: TestData = envelope
            .unseal(
                &DataEnvelopeNamespace::ExampleNamespace,
                crate::traits::tests::TestSymmKey::A(0),
                &mut ctx,
            )
            .unwrap();
        assert_eq!(unsealed_data.field2, 789);
    }

    #[test]
    fn test_namespace_cross_contamination_protection() {
        let data1 = TestData { field2: 111 };
        let data2 = TestData { field2: 222 };

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
