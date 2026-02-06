use serde::{Deserialize, Serialize};
use snow::resolvers::{CryptoResolver, DefaultResolver};

use crate::crypto_provider::noise::messages::TransportMessage;

const KEY_SIZE: usize = 32;
const TAG_SIZE: usize = 16;
const NOISE_MAX_MESSAGE_LEN: usize = 65535;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Cipher {
    ChaChaPoly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistentTransportState {
    cipher: Cipher,
    send_key: [u8; KEY_SIZE],
    receive_key: [u8; KEY_SIZE],
    send_nonce: u64,
    receive_nonce: u64,

    // Rekey-counter says how many times the key has been re-keyed. This enables
    // re-keying and synchronization after re-keying
    send_rekey_counter: u64,
    receive_rekey_counter: u64,
}

impl PersistentTransportState {
    pub(crate) fn new(
        cipher: Cipher,
        send_key: [u8; KEY_SIZE],
        receive_key: [u8; KEY_SIZE],
    ) -> Self {
        Self {
            cipher,
            send_key,
            receive_key,
            send_nonce: 0,
            receive_nonce: 0,
            send_rekey_counter: 0,
            receive_rekey_counter: 0,
        }
    }
}

impl PersistentTransportState {
    pub(crate) fn write_message(&mut self, plaintext: &[u8]) -> TransportMessage {
        // Increase nonce. WARNING: Re-used nonces lead to catastrophic
        // crypto failure. Ensure this increases always.
        self.send_nonce += 1;

        // Encrypt the message
        let cipher = get_cipher_with_key(&self.send_key);
        let mut buffer = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let len = cipher.encrypt(self.send_nonce, &[], plaintext, &mut buffer);
        buffer.truncate(len);

        TransportMessage {
            payload: buffer.into(),
            nonce: self.send_nonce,
            rekey_counter: self.send_rekey_counter,
        }
    }

    pub(crate) fn read_message(
        &mut self,
        transport_message: &TransportMessage,
    ) -> Result<Vec<u8>, ()> {
        if transport_message.nonce <= self.receive_nonce {
            return Err(());
        } else {
            self.receive_nonce = transport_message.nonce;
        }

        // Cannot go back to old keys
        if transport_message.rekey_counter < self.receive_rekey_counter {
            return Err(());
        } else {
            self.rekey_receive(transport_message.rekey_counter);
        }

        // Decrypt
        let mut buffer = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let cipher = get_cipher_with_key(&self.receive_key);
        let len = cipher
            .decrypt(
                transport_message.nonce,
                &[],
                &transport_message.payload,
                &mut buffer,
            )
            .map_err(|_| ())?;
        Ok(buffer[..len].to_vec())
    }

    /// Re-key one-way hashes the symmetric send key and increases the re-key counter. The receiving
    /// side will automatically synchonize to the re-keyed key, on the receive key side. This
    /// ensures that old keys and messages encrypted under these cannot be decrypted after a
    /// re-key.
    #[allow(unused)]
    pub(crate) fn rekey_send(&mut self) {
        self.send_key = rekey(self.send_key);
        self.send_rekey_counter += 1;
    }

    /// Automatically catch-up to the target re-key counter
    pub(crate) fn rekey_receive(&mut self, target_rekey_counter: u64) {
        while self.receive_rekey_counter < target_rekey_counter {
            self.receive_key = rekey(self.receive_key);
            self.receive_rekey_counter += 1;
        }
    }
}

fn get_cipher_with_key(key: &[u8; KEY_SIZE]) -> Box<dyn snow::types::Cipher> {
    let resolver = DefaultResolver;
    let mut cipher = resolver
        .resolve_cipher(&snow::params::CipherChoice::ChaChaPoly)
        .expect("ChaChaPoly should be supported by the resolver");
    cipher.set(key);
    cipher
}

fn rekey(key: [u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    // Rekey according to Section 4.2 of the Noise Specification, with a default
    // implementation guaranteed to be secure for all ciphers.
    let cipher = get_cipher_with_key(&key);
    let mut ciphertext = [0; KEY_SIZE + TAG_SIZE];
    let ciphertext_len = cipher.encrypt(u64::MAX, &[], &[0; KEY_SIZE], &mut ciphertext);
    assert_eq!(ciphertext_len, ciphertext.len());
    let mut new_key = [0u8; KEY_SIZE];
    new_key.copy_from_slice(&ciphertext[..KEY_SIZE]);
    new_key
}

#[cfg(test)]
mod tests {
    use super::{Cipher, KEY_SIZE, PersistentTransportState};

    const TEST_STATE_1: PersistentTransportState = PersistentTransportState {
        cipher: Cipher::ChaChaPoly,
        send_key: [1u8; KEY_SIZE],
        receive_key: [2u8; KEY_SIZE],
        send_nonce: 0,
        receive_nonce: 0,
        send_rekey_counter: 0,
        receive_rekey_counter: 0,
    };
    const TEST_STATE_2: PersistentTransportState = PersistentTransportState {
        cipher: Cipher::ChaChaPoly,
        send_key: [2u8; KEY_SIZE],
        receive_key: [1u8; KEY_SIZE],
        send_nonce: 0,
        receive_nonce: 0,
        send_rekey_counter: 0,
        receive_rekey_counter: 0,
    };

    #[test]
    fn encrypt_decrypt_round_trip_returns_plaintext() {
        let mut sender = TEST_STATE_1.clone();
        let mut receiver = TEST_STATE_2.clone();

        let plaintext = b"noise-transport-message";

        let message = sender.write_message(plaintext);
        let decrypted = receiver
            .read_message(&message)
            .expect("decrypt should succeed for matching nonces");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn replayed_message_fails() {
        let mut sender = TEST_STATE_1.clone();
        let mut receiver = TEST_STATE_2.clone();
        let plaintext = b"noise-transport-message";
        let message = sender.write_message(plaintext);
        let _ = receiver
            .read_message(&message)
            .expect("first decrypt should succeed");
        assert_eq!(receiver.read_message(&message), Err(()));
    }

    #[test]
    fn rekeying_works() {
        let mut sender = TEST_STATE_1.clone();
        let mut receiver = TEST_STATE_2.clone();

        // Send message before rekey
        let plaintext1 = b"message-before-rekey";
        let message1 = sender.write_message(plaintext1);
        let decrypted1 = receiver
            .read_message(&message1)
            .expect("decrypt should succeed for matching nonces");
        assert_eq!(decrypted1, plaintext1);

        // Rekey
        sender.rekey_send();

        // Send another message
        let plaintext2 = b"message-after-rekey";
        let message2 = sender.write_message(plaintext2);
        let decrypted2 = receiver
            .read_message(&message2)
            .expect("decrypt should succeed after rekey");
        assert_eq!(decrypted2, plaintext2);
    }
}
