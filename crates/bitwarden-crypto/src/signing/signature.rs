use ciborium::value::Integer;
use coset::{CborSerializable, CoseSign1, iana::CoapContentFormat};
use serde::Serialize;

use super::{
    SigningNamespace, VerifyingKey, content_type, message::SerializedMessage, namespace,
    signing_key::SigningKey,
};
use crate::{
    CoseSign1Bytes, CryptoError,
    content_format::CoseSign1ContentFormat,
    cose::{CoseSerializable, SIGNING_NAMESPACE},
    error::{EncodingError, SignatureError},
};

/// A signature cryptographically attests to a (namespace, data) pair. The namespace is included in
/// the signature object, the data is not. One data object can be signed multiple times, with
/// different namespaces / by different signers, depending on the application needs.
pub struct Signature(CoseSign1);

impl From<CoseSign1> for Signature {
    fn from(cose_sign1: CoseSign1) -> Self {
        Signature(cose_sign1)
    }
}

impl Signature {
    fn inner(&self) -> &CoseSign1 {
        &self.0
    }

    fn namespace(&self) -> Result<SigningNamespace, CryptoError> {
        namespace(&self.0.protected)
    }

    /// Parses the signature headers and returns the content type of the signed data. The content
    /// type indicates how the serialized message that was signed was encoded.
    pub fn content_type(&self) -> Result<CoapContentFormat, CryptoError> {
        content_type(&self.0.protected)
    }

    /// Verifies the signature of the given serialized message bytes, created by
    /// [`SigningKey::sign_detached`], for the given namespace. The namespace must match the one
    /// used to create the signature.
    ///
    /// The first anticipated consumer will be signed org memberships / emergency access:
    /// <https://bitwarden.atlassian.net/browse/PM-17458>
    pub fn verify(
        &self,
        serialized_message_bytes: &[u8],
        verifying_key: &VerifyingKey,
        namespace: &SigningNamespace,
    ) -> bool {
        if self.inner().protected.header.alg.is_none() {
            return false;
        }

        if self.namespace().ok().as_ref() != Some(namespace) {
            return false;
        }

        self.inner()
            .verify_detached_signature(serialized_message_bytes, &[], |sig, data| {
                verifying_key.verify_raw(sig, data)
            })
            .is_ok()
    }
}

impl SigningKey {
    /// Signs the given payload with the signing key, under a given [`SigningNamespace`].
    /// This returns a [`Signature`] object, that does not contain the payload.
    /// The payload must be stored separately, and needs to be provided when verifying the
    /// signature.
    ///
    /// This should be used when multiple signers are required, or when signatures need to be
    /// replaceable without re-uploading the object, or if the signed object should be parseable
    /// by the server side, without the use of COSE on the server.
    /// ```
    /// use bitwarden_crypto::{SigningNamespace, SignatureAlgorithm, SigningKey};
    /// use serde::{Serialize, Deserialize};
    ///
    /// const EXAMPLE_NAMESPACE: SigningNamespace = SigningNamespace::SignedPublicKey;
    ///
    /// #[derive(Serialize, Deserialize, Debug, PartialEq)]
    /// struct TestMessage {
    ///  field1: String,
    /// }
    ///
    /// let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    /// let message = TestMessage {
    ///  field1: "Test message".to_string(),
    /// };
    /// let namespace = EXAMPLE_NAMESPACE;
    /// let (signature, serialized_message) = signing_key.sign_detached(&message, &namespace).unwrap();
    /// // Verification
    /// let verifying_key = signing_key.to_verifying_key();
    /// assert!(signature.verify(&serialized_message.as_bytes(), &verifying_key, &namespace));
    /// ```
    pub fn sign_detached<Message: Serialize>(
        &self,
        message: &Message,
        namespace: &SigningNamespace,
    ) -> Result<(Signature, SerializedMessage), CryptoError> {
        let serialized_message = SerializedMessage::encode(message)?;
        Ok((
            self.sign_detached_bytes(&serialized_message, namespace),
            serialized_message,
        ))
    }

    /// Given a serialized message, signature, this counter-signs the message. That is, if multiple
    /// parties want to sign the same message, one party creates the initial message, and the
    /// other parties then counter-sign it, and submit their signatures. This can be done as
    /// follows: ```
    /// let alice_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    /// let bob_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    ///
    /// let message = TestMessage {
    ///    field1: "Test message".to_string(),
    /// };
    /// let namespace = SigningNamespace::ExampleNamespace;
    /// let (signature, serialized_message) = alice_key.sign_detached(&message,
    /// &namespace).unwrap();\ // Alice shares (signature, serialized_message) with Bob.
    /// // Bob verifies the contents of serialized_message using application logic, then signs it:
    /// let (bob_signature, serialized_message) = bob_key.counter_sign(&serialized_message,
    /// &signature, &namespace).unwrap(); ```
    pub fn counter_sign_detached(
        &self,
        serialized_message_bytes: Vec<u8>,
        initial_signature: &Signature,
        namespace: &SigningNamespace,
    ) -> Result<Signature, CryptoError> {
        // The namespace should be passed in to make sure the namespace the counter-signer is
        // expecting to sign for is the same as the one that the signer used
        if initial_signature.namespace()? != *namespace {
            return Err(SignatureError::InvalidNamespace.into());
        }

        Ok(self.sign_detached_bytes(
            &SerializedMessage::from_bytes(
                serialized_message_bytes,
                initial_signature.content_type()?,
            ),
            namespace,
        ))
    }

    /// Signs the given payload with the signing key, under a given namespace.
    /// This is is the underlying implementation of the `sign_detached` method, and takes
    /// a raw byte array as input.
    fn sign_detached_bytes(
        &self,
        message: &SerializedMessage,
        namespace: &SigningNamespace,
    ) -> Signature {
        Signature::from(
            coset::CoseSign1Builder::new()
                .protected(
                    coset::HeaderBuilder::new()
                        .algorithm(self.cose_algorithm())
                        .key_id((&self.id).into())
                        .content_format(message.content_type())
                        .value(
                            SIGNING_NAMESPACE,
                            ciborium::Value::Integer(Integer::from(namespace.as_i64())),
                        )
                        .build(),
                )
                .create_detached_signature(message.as_bytes(), &[], |pt| self.sign_raw(pt))
                .build(),
        )
    }
}

impl CoseSerializable<CoseSign1ContentFormat> for Signature {
    fn from_cose(bytes: &CoseSign1Bytes) -> Result<Self, EncodingError> {
        let cose_sign1 = CoseSign1::from_slice(bytes.as_ref())
            .map_err(|_| EncodingError::InvalidCoseEncoding)?;
        Ok(Signature(cose_sign1))
    }

    fn to_cose(&self) -> CoseSign1Bytes {
        self.0
            .clone()
            .to_vec()
            .expect("Signature is always serializable")
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoseKeyBytes, SignatureAlgorithm};

    const VERIFYING_KEY: &[u8] = &[
        166, 1, 1, 2, 80, 55, 131, 40, 191, 230, 137, 76, 182, 184, 139, 94, 152, 45, 63, 13, 71,
        3, 39, 4, 129, 2, 32, 6, 33, 88, 32, 93, 213, 35, 177, 81, 219, 226, 241, 147, 140, 238,
        32, 34, 183, 213, 107, 227, 92, 75, 84, 208, 47, 198, 80, 18, 188, 172, 145, 184, 154, 26,
        170,
    ];
    const SIGNATURE: &[u8] = &[
        132, 88, 30, 164, 1, 39, 3, 24, 60, 4, 80, 55, 131, 40, 191, 230, 137, 76, 182, 184, 139,
        94, 152, 45, 63, 13, 71, 58, 0, 1, 56, 127, 32, 160, 246, 88, 64, 206, 83, 177, 184, 37,
        103, 128, 39, 120, 174, 61, 4, 29, 184, 68, 46, 47, 203, 47, 246, 108, 160, 169, 114, 7,
        165, 119, 198, 3, 209, 52, 249, 89, 31, 156, 255, 212, 75, 224, 78, 183, 37, 174, 63, 112,
        70, 219, 246, 19, 213, 17, 121, 249, 244, 23, 182, 36, 193, 175, 55, 250, 65, 250, 6,
    ];
    const SERIALIZED_MESSAGE: &[u8] = &[
        161, 102, 102, 105, 101, 108, 100, 49, 108, 84, 101, 115, 116, 32, 109, 101, 115, 115, 97,
        103, 101,
    ];

    #[test]
    fn test_cose_roundtrip_encode_signature() {
        let signature = Signature::from_cose(&CoseSign1Bytes::from(SIGNATURE)).unwrap();
        let cose_bytes = signature.to_cose();
        let decoded_signature = Signature::from_cose(&cose_bytes).unwrap();
        assert_eq!(signature.inner(), decoded_signature.inner());
    }

    #[test]
    fn test_verify_testvector() {
        let verifying_key = VerifyingKey::from_cose(&CoseKeyBytes::from(VERIFYING_KEY)).unwrap();
        let signature = Signature::from_cose(&CoseSign1Bytes::from(SIGNATURE)).unwrap();
        let serialized_message =
            SerializedMessage::from_bytes(SERIALIZED_MESSAGE.to_vec(), CoapContentFormat::Cbor);

        let namespace = SigningNamespace::ExampleNamespace;

        assert!(signature.verify(serialized_message.as_ref(), &verifying_key, &namespace));
    }

    #[test]
    fn test_sign_detached_roundtrip() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let message = "Test message";
        let namespace = SigningNamespace::ExampleNamespace;

        let (signature, serialized_message) =
            signing_key.sign_detached(&message, &namespace).unwrap();

        let verifying_key = signing_key.to_verifying_key();
        assert!(signature.verify(serialized_message.as_ref(), &verifying_key, &namespace));
    }

    #[test]
    fn test_countersign_detatched() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let message = "Test message";
        let namespace = SigningNamespace::ExampleNamespace;

        let (signature, serialized_message) =
            signing_key.sign_detached(&message, &namespace).unwrap();

        let countersignature = signing_key
            .counter_sign_detached(
                serialized_message.as_bytes().to_vec(),
                &signature,
                &namespace,
            )
            .unwrap();

        let verifying_key = signing_key.to_verifying_key();
        assert!(countersignature.verify(serialized_message.as_ref(), &verifying_key, &namespace));
    }

    #[test]
    fn test_fail_namespace_changed() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let message = "Test message";
        let namespace = SigningNamespace::ExampleNamespace;

        let (signature, serialized_message) =
            signing_key.sign_detached(&message, &namespace).unwrap();

        let different_namespace = SigningNamespace::ExampleNamespace2;
        let verifying_key = signing_key.to_verifying_key();

        assert!(!signature.verify(
            serialized_message.as_ref(),
            &verifying_key,
            &different_namespace
        ));
    }
}
