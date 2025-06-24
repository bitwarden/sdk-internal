//! This example demonstrates how to create signatures and countersignatures for a message, and how
//! to verify them.

use bitwarden_crypto::{CoseSerializable, CoseSign1Bytes, SigningNamespace};
use serde::{Deserialize, Serialize};

const EXAMPLE_NAMESPACE: &SigningNamespace = &SigningNamespace::SignedPublicKey;

fn main() {
    // Alice wants to create a message, sign it, and send it to Bob. Bob should sign it too, and
    // then finally Charlie should be able to verify both.

    // Setup
    let mut mock_server = MockServer::new();
    let alice_signature_key =
        bitwarden_crypto::SigningKey::make(bitwarden_crypto::SignatureAlgorithm::Ed25519);
    let alice_verifying_key = alice_signature_key.to_verifying_key();
    let bob_signature_key =
        bitwarden_crypto::SigningKey::make(bitwarden_crypto::SignatureAlgorithm::Ed25519);
    let bob_verifying_key = bob_signature_key.to_verifying_key();
    // We assume bob knows and trusts this verifying key previously via e.g. fingerprints or
    // auditable key directory.

    // Alice creates a message
    #[derive(Serialize, Deserialize)]
    struct MessageToCharlie {
        content: String,
    }
    let (signature, serialized_message) = alice_signature_key
        .sign_detached(
            &MessageToCharlie {
                content: "Hello Charlie, this is Alice and Bob!".to_string(),
            },
            // The namespace should be unique per message type. It ensures no cross protocol
            // attacks can happen.
            EXAMPLE_NAMESPACE,
        )
        .expect("Failed to sign message");

    // Alice sends the signed object to Bob
    mock_server.upload("signature", signature.to_cose().to_vec());
    mock_server.upload("serialized_message", serialized_message.as_bytes().to_vec());

    // Bob retrieves the signed object from the server
    let retrieved_signature = bitwarden_crypto::Signature::from_cose(&CoseSign1Bytes::from(
        mock_server
            .download("signature")
            .expect("Failed to download signature")
            .clone(),
    ))
    .expect("Failed to deserialize signature");
    let retrieved_serialized_message = bitwarden_crypto::SerializedMessage::from_bytes(
        mock_server
            .download("serialized_message")
            .expect("Failed to download serialized message")
            .clone(),
        retrieved_signature
            .content_type()
            .expect("Failed to get content type from signature"),
    );

    // Bob verifies the signature using Alice's verifying key
    if !retrieved_signature.verify(
        retrieved_serialized_message.as_bytes(),
        &alice_verifying_key,
        EXAMPLE_NAMESPACE,
    ) {
        panic!("Alice's signature verification failed");
    }

    // Bob signs the message for Charlie
    let bobs_signature = bob_signature_key
        .counter_sign_detached(
            retrieved_serialized_message.as_bytes().to_vec(),
            &retrieved_signature,
            EXAMPLE_NAMESPACE,
        )
        .expect("Failed to counter sign message");
    // Bob sends the counter signature to Charlie
    mock_server.upload("bobs_signature", bobs_signature.to_cose().to_vec());

    // Charlie retrieves the signatures, and the message
    let retrieved_serialized_message = bitwarden_crypto::SerializedMessage::from_bytes(
        mock_server
            .download("serialized_message")
            .expect("Failed to download serialized message")
            .clone(),
        retrieved_signature
            .content_type()
            .expect("Failed to get content type from signature"),
    );
    let retrieved_alice_signature = bitwarden_crypto::Signature::from_cose(&CoseSign1Bytes::from(
        mock_server
            .download("signature")
            .expect("Failed to download Alice's signature")
            .clone(),
    ))
    .expect("Failed to deserialize Alice's signature");
    let retrieved_bobs_signature = bitwarden_crypto::Signature::from_cose(&CoseSign1Bytes::from(
        mock_server
            .download("bobs_signature")
            .expect("Failed to download Bob's signature")
            .clone(),
    ))
    .expect("Failed to deserialize Bob's signature");

    // Charlie verifies Alice's signature
    if !retrieved_alice_signature.verify(
        retrieved_serialized_message.as_bytes(),
        &alice_verifying_key,
        EXAMPLE_NAMESPACE,
    ) {
        panic!("Alice's signature verification failed");
    }
    // Charlie verifies Bob's signature
    if !retrieved_bobs_signature.verify(
        retrieved_serialized_message.as_bytes(),
        &bob_verifying_key,
        EXAMPLE_NAMESPACE,
    ) {
        panic!("Bob's signature verification failed");
    }
    // Charlie can now access the content of the message
    let verified_message: MessageToCharlie = retrieved_serialized_message
        .decode()
        .expect("Failed to decode serialized message");
    println!(
        "Charlie received a message from Alice and Bob: {}",
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
