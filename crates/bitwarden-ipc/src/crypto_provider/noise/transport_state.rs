use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use tracing::info;

use crate::crypto_provider::noise::handshake::{HandshakeFinishMessage, HandshakeStartMessage};

// Ref: http://noiseprotocol.org/noise.html#message-format
const KEY_SIZE: usize = 32;
const NOISE_MAX_MESSAGE_LEN: usize = 65535;

/// Supported ciphers for the transport mode of noise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Cipher {
    ChaCha20Poly1305 = 0,
    Aes256Gcm = 1,
}

impl Default for Cipher {
    fn default() -> Self {
        if cfg!(feature = "fips") {
            Self::Aes256Gcm
        } else {
            Self::ChaCha20Poly1305
        }
    }
}

/// A newtype for symmetric keys used in noise. A noise key is always 256-bits.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SymmetricKey(pub(crate) [u8; KEY_SIZE]);

/// Implement Debug manually to avoid accidentally logging the key material.
impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SymmetricKey").finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistentTransportState {
    cipher: Cipher,

    // Noise has two keys, the initatior to responder key (i2r) and the responder to initiator key (r2i).
    // For the initiator, send_key = i2r and receive_key = r2i.
    // For the responder, send_key = r2i and receive_key = i2r.
    send_key: SymmetricKey,
    receive_key: SymmetricKey,

    // Noise transport messages include a nonce that must be unique for every message encrypted with the same key.
    // The nonce increases monotonically with every sent/received message and is never reset to a lower value.
    // Re-using nonces results in catastrophic cryptographic failure.
    send_nonce: u64,
    // For receiving, skipping nonces is alowed, but never going back.
    receive_nonce: u64,

    // Whether to allow payloads to be sent via this transport state
    // Otherwise, only handshake packets are allowed.
    allow_payload_sending: bool,
    last_handshake_time: u64,
}

impl PersistentTransportState {
    /// Create a new transport state with the given keys and cipher.
    pub(crate) fn new(send_key: SymmetricKey, receive_key: SymmetricKey, cipher: Cipher) -> Self {
        Self {
            cipher,
            send_key,
            receive_key,
            send_nonce: 0,
            receive_nonce: 0,
            allow_payload_sending: true,
            last_handshake_time: current_epoch_secs(),
        }
    }

    // Create a transport state with null keys. WARNING: This means that NO
    // security is provided by the noise transport encryption until a re-handshake occurs.
    pub(crate) fn null() -> Self {
        Self {
            cipher: Cipher::default(),
            send_key: SymmetricKey([0u8; KEY_SIZE]),
            receive_key: SymmetricKey([0u8; KEY_SIZE]),
            send_nonce: 0,
            receive_nonce: 0,
            allow_payload_sending: false,
            last_handshake_time: 0,
        }
    }

    /// Whether this transport state allows sending payload messages.
    pub(crate) fn allow_payload_sending(&self) -> bool {
        self.allow_payload_sending
    }

    pub(crate) fn last_handshake_epoch_secs(&self) -> u64 {
        self.last_handshake_time
    }
}

/// A newtype for a plaintext payload carried inside the encrypted noise tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Payload(pub(crate) Vec<u8>);

impl From<Vec<u8>> for Payload {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Message that is sent inside of the noise tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Message {
    Payload {
        // The plaintext payload that is sent over the noise tunnel.
        payload: Payload,
    },
    HandshakeStart {
        // The noise frame that is created by the handshake initiator
        handshake_start: HandshakeStartMessage,
    },
    HandshakeFinish {
        // The noise frame that is created by the handshake responder
        handshake_finish: HandshakeFinishMessage,
    },
}

impl From<HandshakeStartMessage> for Message {
    fn from(value: HandshakeStartMessage) -> Self {
        Message::HandshakeStart {
            handshake_start: value,
        }
    }
}

impl From<HandshakeFinishMessage> for Message {
    fn from(value: HandshakeFinishMessage) -> Self {
        Message::HandshakeFinish {
            handshake_finish: value,
        }
    }
}

impl Message {
    pub(super) fn to_cbor(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).expect("Ciborium serialization should not fail");
        buffer
    }

    pub(super) fn from_cbor(buffer: &[u8]) -> Result<Self, ()> {
        ciborium::from_reader(buffer).map_err(|_| ())
    }
}

impl PersistentTransportState {
    pub(crate) fn send(&mut self, message: Message) -> Result<TransportFrame, ()> {
        // Guard against sending payload messages if not allowed by the transport state
        match message {
            Message::Payload { .. } if !self.allow_payload_sending => return Err(()),
            _ => {}
        }

        // Increase nonce. WARNING: Re-used nonces lead to catastrophic
        // crypto failure. Ensure this increases always.
        self.send_nonce += 1;

        // Encrypt the message
        let cipher = get_cipher_with_key(&self.send_key, &self.cipher);
        let mut buffer = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let len = cipher.encrypt(
            self.send_nonce,
            &[],
            message.to_cbor().as_slice(),
            &mut buffer,
        );
        buffer.truncate(len);

        Ok(TransportFrame {
            payload: buffer.into(),
            nonce: self.send_nonce,
        })
    }

    pub(crate) fn receive(
        &mut self,
        transport_frame: &TransportFrame,
    ) -> Result<Message, ReceiveError> {
        // Try decryption with current receive key first.
        if transport_frame.nonce > self.receive_nonce {
            if let Ok(plaintext) = self.try_decrypt(&self.receive_key, transport_frame) {
                self.receive_nonce = transport_frame.nonce;
                Message::from_cbor(&plaintext).map_err(|_| ReceiveError::Parsing)
            } else {
                info!("Failed to decrypt incoming IPC message");
                Err(ReceiveError::Decryption)
            }
        } else {
            info!("Ipc message was replayed! Discarding...");
            Err(ReceiveError::NonceReplay)
        }
    }

    fn try_decrypt(
        &self,
        key: &SymmetricKey,
        transport_message: &TransportFrame,
    ) -> Result<Vec<u8>, ()> {
        let mut buffer = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let cipher = get_cipher_with_key(key, &self.cipher);
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
}

#[derive(Debug, Clone)]
pub(crate) enum ReceiveError {
    NonceReplay,
    Decryption,
    Parsing,
}

/// Returns the current time as seconds since the Unix epoch.
pub(crate) fn current_epoch_secs() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .expect("System clock is before Unix epoch")
        .as_secs()
}

fn get_cipher_with_key(key: &SymmetricKey, cipher: &Cipher) -> Box<dyn snow::types::Cipher> {
    let resolver = DefaultResolver;
    match cipher {
        Cipher::ChaCha20Poly1305 => {
            let mut cipher = resolver
                .resolve_cipher(&snow::params::CipherChoice::ChaChaPoly)
                .expect("ChaChaPoly should be supported by the resolver");
            cipher.set(&key.0);
            cipher
        }
        Cipher::Aes256Gcm => {
            let mut cipher = resolver
                .resolve_cipher(&snow::params::CipherChoice::AESGCM)
                .expect("AESGCM should be supported by the resolver");
            cipher.set(&key.0);
            cipher
        }
    }
}

/// Wire format — always encrypted with current symmetric keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TransportFrame {
    pub(crate) payload: ByteBuf,
    pub(crate) nonce: u64,
}

impl TransportFrame {
    pub(crate) fn to_cbor(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).expect("Ciborium serialization should not fail");
        buffer
    }

    pub(crate) fn from_cbor(buffer: &[u8]) -> Result<Self, ()> {
        ciborium::from_reader(buffer).map_err(|_| ())
    }
}

#[cfg(test)]
pub(crate) fn assert_matching_pair(
    state_1: &PersistentTransportState,
    state_2: &PersistentTransportState,
) {
    assert_eq!(state_1.send_key.0, state_2.receive_key.0);
    assert_eq!(state_1.receive_key.0, state_2.send_key.0);
}

#[cfg(test)]
pub(crate) fn assert_non_null(state: &PersistentTransportState) {
    assert_ne!(state.send_key.0, [0u8; KEY_SIZE]);
    assert_ne!(state.receive_key.0, [0u8; KEY_SIZE]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> (SymmetricKey, SymmetricKey) {
        let send_key = SymmetricKey([1u8; KEY_SIZE]);
        let receive_key = SymmetricKey([2u8; KEY_SIZE]);
        (send_key, receive_key)
    }

    fn make_pair() -> (PersistentTransportState, PersistentTransportState) {
        let (send_key, receive_key) = test_keys();
        let sender =
            PersistentTransportState::new(send_key.clone(), receive_key.clone(), Cipher::default());
        let receiver =
            PersistentTransportState::new(receive_key, send_key, Cipher::default());
        (sender, receiver)
    }

    #[test]
    fn test_message_cbor_round_trip() {
        let message = Message::Payload {
            payload: b"hello world".to_vec().into(),
        };
        let cbor = message.to_cbor();
        let deserialized = Message::from_cbor(&cbor).expect("deserialization should succeed");
        match deserialized {
            Message::Payload { payload } => assert_eq!(payload.as_ref(), b"hello world"),
            _ => panic!("expected Payload variant"),
        }
    }

    #[test]
    fn test_message_cbor_invalid_bytes_returns_error() {
        let result = Message::from_cbor(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_and_receive_payload() {
        let (mut sender, mut receiver) = make_pair();

        let message = Message::Payload {
            payload: b"ping".to_vec().into(),
        };
        let frame = sender.send(message).expect("send should succeed");
        let received = receiver.receive(&frame).expect("receive should succeed");

        match received {
            Message::Payload { payload } => assert_eq!(payload.as_ref(), b"ping"),
            _ => panic!("expected Payload variant"),
        }
    }

    #[test]
    fn test_send_and_receive_multiple_messages() {
        let (mut sender, mut receiver) = make_pair();

        for i in 0..5 {
            let message = Message::Payload {
                payload: format!("msg-{i}").into_bytes().into(),
            };
            let frame = sender.send(message).expect("send should succeed");
            let received = receiver.receive(&frame).expect("receive should succeed");

            match received {
                Message::Payload { payload } => {
                    assert_eq!(payload.as_ref(), format!("msg-{i}").as_bytes());
                }
                _ => panic!("expected Payload variant"),
            }
        }
    }

    #[test]
    fn test_nonce_replay_is_rejected() {
        let (mut sender, mut receiver) = make_pair();

        let message = Message::Payload {
            payload: b"first".to_vec().into(),
        };
        let frame = sender.send(message).expect("send should succeed");

        // First receive succeeds
        let replayed_frame = frame.clone();
        receiver
            .receive(&frame)
            .expect("first receive should succeed");

        // Replaying the same frame (same nonce) should fail
        let result = receiver.receive(&replayed_frame);
        assert!(result.is_err(), "replayed frame must be rejected");
    }

    #[test]
    fn test_old_nonce_is_rejected() {
        let (mut sender, mut receiver) = make_pair();

        // Send two messages
        let msg1 = Message::Payload {
            payload: b"first".to_vec().into(),
        };
        let msg2 = Message::Payload {
            payload: b"second".to_vec().into(),
        };
        let frame1 = sender.send(msg1).expect("send should succeed");
        let frame2 = sender.send(msg2).expect("send should succeed");

        // Receive the second message first (higher nonce)
        receiver.receive(&frame2).expect("receive should succeed");

        // Now try to receive the first message (lower nonce) — should be rejected
        let result = receiver.receive(&frame1);
        assert!(result.is_err(), "out-of-order lower nonce must be rejected");
    }

    #[test]
    fn test_decryption_with_tampered_ciphertext_fails() {
        let (mut sender, mut receiver) = make_pair();

        let message = Message::Payload {
            payload: b"important".to_vec().into(),
        };
        let mut frame = sender.send(message).expect("send should succeed");

        // Tamper with the ciphertext
        frame.payload[0] ^= 0xFF;

        let result = receiver.receive(&frame);
        assert!(result.is_err(), "tampered ciphertext must fail decryption");
    }

    #[test]
    fn test_null_state_rejects_payload_send() {
        let mut state = PersistentTransportState::null();
        let message = Message::Payload {
            payload: b"hello".to_vec().into(),
        };
        let result = state.send(message);
        assert!(
            result.is_err(),
            "null state must not allow sending payloads"
        );
    }
}
