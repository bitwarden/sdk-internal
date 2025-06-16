//! Signing is used to assert integrity of a message to others or to oneself.
//!
//! Signing and signature verification operations are divided into three layers here:
//! - (public) High-level: Give a struct, namespace, and get a signed object or signature +
//!   serialized message. Purpose: Serialization should not be decided by the consumer of this
//!   interface, but rather by the signing implementation. Each consumer shouldn't have to make the
//!   decision on how to serialize. Further, the serialization format is written to the signature
//!   object, and verified.
//!
//! - Mid-level: Give a byte array, content format, namespace, and get a signed object or signature.
//!   Purpose: All signatures should be domain-separated, so that any proofs only need to consider
//!   the allowed messages under the current namespace, and cross-protocol attacks are not possible.
//!
//! - Low-level: Give a byte array, and get a signature. Purpose: This just implements the signing
//!   of byte arrays. Digital signature schemes generally just care about a set of input bytes to
//!   sign; and this operation implements that per-supported digital signature scheme. To add
//!   support for a new scheme, only this operation needs to be implemented for the new signing key
//!   type. This is implemented in the ['signing_key'] and ['verifying_key'] modules.
//!
//! Signing operations are split into two types. The mid-level and high-level operations are
//! implemented for each type respectively.
//! - Sign: Create a [`signed_object::SignedObject`] that contains the payload. Purpose: If only one
//!   signature is needed for an object then it is simpler to keep the signature and payload
//!   together in one blob, so they cannot be separated.
//!
//! - Sign detached: Create a [`signature::Signature`] that does not contain the payload; but the
//!   serialized payload is returned. Purpose: If multiple signatures are needed for one object,
//!   then sign detached can be used.

mod cose;
use cose::*;
mod namespace;
pub use namespace::SigningNamespace;
mod signed_object;
pub use signed_object::SignedObject;
mod signature;
pub use signature::Signature;
mod signing_key;
pub use signing_key::SigningKey;
mod verifying_key;
pub use verifying_key::VerifyingKey;
mod message;
pub use message::SerializedMessage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify_next::Tsify, wasm_bindgen::prelude::*};

/// The type of key / signature scheme used for signing and verifying.
#[derive(Serialize, Deserialize, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum SignatureAlgorithm {
    /// Ed25519 is the modern, secure recommended option for digital signatures on eliptic curves.
    Ed25519,
}

impl SignatureAlgorithm {
    /// Returns the currently accepted safe algorithm for new keys.
    pub fn default_algorithm() -> Self {
        SignatureAlgorithm::Ed25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoseSerializable;

    #[derive(Deserialize, Debug, PartialEq, Serialize)]
    struct TestMessage {
        field1: String,
    }

    /// The function used to create the test vectors below, and can be used to re-generate them.
    /// Once rolled out to user accounts, this function can be removed, because at that point we
    /// cannot introduce format-breaking changes anymore.
    #[test]
    fn make_test_vectors() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let verifying_key = signing_key.to_verifying_key();
        let test_message = TestMessage {
            field1: "Test message".to_string(),
        };
        let (signature, serialized_message) = signing_key
            .sign_detached(&test_message, &SigningNamespace::ExampleNamespace)
            .unwrap();
        let signed_object = signing_key
            .sign(&test_message, &SigningNamespace::ExampleNamespace)
            .unwrap();
        let raw_signed_array = signing_key.sign_raw("Test message".as_bytes());
        println!("const SIGNING_KEY: &[u8] = &{:?};", signing_key.to_cose());
        println!(
            "const VERIFYING_KEY: &[u8] = &{:?};",
            verifying_key.to_cose()
        );
        println!("const SIGNATURE: &[u8] = &{:?};", signature.to_cose());
        println!(
            "const SERIALIZED_MESSAGE: &[u8] = &{:?};",
            serialized_message.as_bytes()
        );
        println!(
            "const SIGNED_OBJECT: &[u8] = &{:?};",
            signed_object.to_cose()
        );
        println!(
            "const SIGNED_OBJECT_RAW: &[u8] = &{:?};",
            raw_signed_array.as_slice()
        );
    }
}
