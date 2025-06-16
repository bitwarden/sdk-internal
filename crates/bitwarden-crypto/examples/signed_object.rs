//! This example demonstrates how to sign and verify structs.

use bitwarden_crypto::{CoseSerializable, SignedObject, SigningNamespace};
use serde::{Deserialize, Serialize};

const EXAMPLE_NAMESPACE: &SigningNamespace = &SigningNamespace::SignedPublicKey;

fn main() {
    // Alice wants to create a message, for which Bob is sure that Alice signed it. Bob should only
    // access the payload if he verified the signatures validity.

    // Setup
    let mut mock_server = MockServer::new();
    let alice_signature_key =
        bitwarden_crypto::SigningKey::make(bitwarden_crypto::SignatureAlgorithm::Ed25519);
    let alice_verifying_key = alice_signature_key.to_verifying_key();
    // We assume bob knows and trusts this verifying key previously via e.g. fingerprints or
    // auditable key directory.

    // Alice creates a message
    #[derive(Serialize, Deserialize)]
    struct MessageToBob {
        content: String,
    }
    let signed_object = alice_signature_key
        .sign(
            &MessageToBob {
                content: "Hello Bob, this is Alice!".to_string(),
            },
            // The namespace should be unique per message type. It ensures no cross protocol
            // attacks can happen.
            EXAMPLE_NAMESPACE,
        )
        .expect("Failed to sign message");

    // Alice sends the signed object to Bob
    mock_server.upload("signed_object", signed_object.to_cose());

    // Bob retrieves the signed object from the server
    let retrieved_signed_object = SignedObject::from_cose(
        mock_server
            .download("signed_object")
            .expect("Failed to download signed object"),
    )
    .expect("Failed to deserialize signed object");
    // Bob verifies the signed object using Alice's verifying key
    let verified_message: MessageToBob = retrieved_signed_object
        .verify_and_unwrap(&alice_verifying_key, EXAMPLE_NAMESPACE)
        .expect("Failed to verify signed object");
    // Bob can now access the content of the message
    println!(
        "Bob received a message from Alice: {}",
        verified_message.content
    );
}

pub(crate) struct MockServer {
    map: std::collections::HashMap<String, Vec<u8>>,
}

impl MockServer {
    pub(crate) fn new() -> Self {
        MockServer {
            map: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn upload(&mut self, key: &str, value: Vec<u8>) {
        self.map.insert(key.to_string(), value);
    }

    pub(crate) fn download(&self, key: &str) -> Option<&Vec<u8>> {
        self.map.get(key)
    }
}
