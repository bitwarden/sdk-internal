#![allow(missing_docs)]
use bitwarden_noise::{
    create_noise_protocol, destroy_noise_protocol, generate_keypair, noise_decrypt_message,
    noise_encrypt_message, noise_is_handshake_complete, noise_read_message, noise_split,
    noise_write_message,
};

#[test]
fn test_noise_handshake_and_encryption() {
    // Generate keypairs for both parties
    let initiator_keypair = generate_keypair().expect("Failed to generate initiator keypair");
    let responder_keypair = generate_keypair().expect("Failed to generate responder keypair");

    // Create initiator and responder
    let initiator = create_noise_protocol(true, Some(initiator_keypair.secret_key()), None)
        .expect("Failed to create initiator");
    let responder = create_noise_protocol(false, Some(responder_keypair.secret_key()), None)
        .expect("Failed to create responder");

    // Perform handshake
    // Message 1: initiator -> responder
    let msg1 = noise_write_message(initiator, None).expect("Failed to write message 1");
    let _payload1 = noise_read_message(responder, msg1).expect("Failed to read message 1");

    // Message 2: responder -> initiator
    let msg2 = noise_write_message(responder, None).expect("Failed to write message 2");
    let _payload2 = noise_read_message(initiator, msg2).expect("Failed to read message 2");

    // Message 3: initiator -> responder
    let msg3 = noise_write_message(initiator, None).expect("Failed to write message 3");
    let _payload3 = noise_read_message(responder, msg3).expect("Failed to read message 3");

    // Complete handshake
    noise_split(initiator).expect("Failed to split initiator");
    noise_split(responder).expect("Failed to split responder");

    // Verify handshake is complete
    assert!(
        noise_is_handshake_complete(initiator).expect("Failed to check initiator handshake"),
        "Initiator handshake should be complete"
    );
    assert!(
        noise_is_handshake_complete(responder).expect("Failed to check responder handshake"),
        "Responder handshake should be complete"
    );

    // Test encryption/decryption
    let plaintext = b"Hello, Noise Protocol!";

    // Initiator sends to responder
    let ciphertext =
        noise_encrypt_message(initiator, plaintext.to_vec()).expect("Failed to encrypt message");
    let decrypted =
        noise_decrypt_message(responder, ciphertext).expect("Failed to decrypt message");
    assert_eq!(
        decrypted, plaintext,
        "Decrypted message should match plaintext"
    );

    // Responder sends to initiator
    let ciphertext2 =
        noise_encrypt_message(responder, plaintext.to_vec()).expect("Failed to encrypt message");
    let decrypted2 =
        noise_decrypt_message(initiator, ciphertext2).expect("Failed to decrypt message");
    assert_eq!(
        decrypted2, plaintext,
        "Decrypted message should match plaintext"
    );

    // Clean up
    destroy_noise_protocol(initiator).expect("Failed to destroy initiator");
    destroy_noise_protocol(responder).expect("Failed to destroy responder");
}

#[test]
fn test_noise_with_psk() {
    let psk = vec![42u8; 32]; // 32-byte pre-shared key

    // Create initiator and responder with PSK
    let initiator = create_noise_protocol(true, None, Some(psk.clone()))
        .expect("Failed to create initiator with PSK");
    let responder =
        create_noise_protocol(false, None, Some(psk)).expect("Failed to create responder with PSK");

    // Perform handshake
    let msg1 = noise_write_message(initiator, None).expect("Failed to write message 1");
    noise_read_message(responder, msg1).expect("Failed to read message 1");

    let msg2 = noise_write_message(responder, None).expect("Failed to write message 2");
    noise_read_message(initiator, msg2).expect("Failed to read message 2");

    let msg3 = noise_write_message(initiator, None).expect("Failed to write message 3");
    noise_read_message(responder, msg3).expect("Failed to read message 3");

    // Complete handshake
    noise_split(initiator).expect("Failed to split initiator");
    noise_split(responder).expect("Failed to split responder");

    // Verify handshake is complete
    assert!(noise_is_handshake_complete(initiator).unwrap());
    assert!(noise_is_handshake_complete(responder).unwrap());

    // Clean up
    destroy_noise_protocol(initiator).unwrap();
    destroy_noise_protocol(responder).unwrap();
}
