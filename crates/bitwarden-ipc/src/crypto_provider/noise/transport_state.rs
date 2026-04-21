use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use tracing::warn;

use crate::crypto_provider::noise::NOISE_MAX_MESSAGE_LEN;

// Ref: http://noiseprotocol.org/noise.html#message-format
const KEY_SIZE: usize = 32;

/// Supported ciphers for the transport mode of noise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum TransportCipher {
    ChaCha20Poly1305 = 0,
    Aes256Gcm = 1,
}

impl Default for TransportCipher {
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
pub(super) struct SymmetricKey(pub(crate) [u8; KEY_SIZE]);

/// Implement Debug manually to avoid accidentally logging the key material.
impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey").finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistentTransportState {
    // The symmetric algorithm used for transport encryption
    transport_cipher: TransportCipher,

    // Noise has two keys, the initiator to responder key (i2r) and the responder to initiator key
    // (r2i). For the initiator, send_key = i2r and receive_key = r2i.
    // For the responder, send_key = r2i and receive_key = i2r.
    send_key: SymmetricKey,
    receive_key: SymmetricKey,

    // Noise transport messages include a nonce that must be unique for every message encrypted
    // with the same key. The nonce increases monotonically with every sent/received message
    // and is never reset to a lower value. Re-using nonces results in catastrophic
    // cryptographic failure.
    send_nonce: u64,
    // For receiving, skipping nonces is allowed, but never going back.
    receive_nonce: u64,

    last_handshake_time: u64,
}

impl PersistentTransportState {
    /// Create a new transport state with the given keys and cipher.
    pub(crate) fn new(
        send_key: SymmetricKey,
        receive_key: SymmetricKey,
        transport_cipher: TransportCipher,
    ) -> Self {
        Self {
            transport_cipher,
            send_key,
            receive_key,
            send_nonce: 0,
            receive_nonce: 0,
            last_handshake_time: current_epoch_secs(),
        }
    }

    pub(crate) fn should_rehandshake(&self, rehandshake_interval_secs: u64) -> bool {
        self.is_older_than(current_epoch_secs(), rehandshake_interval_secs)
    }

    pub(crate) fn is_older_than(&self, now_epoch_secs: u64, max_age_secs: u64) -> bool {
        now_epoch_secs.saturating_sub(self.last_handshake_time) > max_age_secs
    }

    #[cfg(test)]
    pub(crate) fn set_last_handshake_epoch_secs_for_test(&mut self, epoch_secs: u64) {
        self.last_handshake_time = epoch_secs;
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

impl PersistentTransportState {
    /// Encrypts the message, mutates the state and returns the transport frame to be sent over
    /// IPC.
    pub(crate) fn send(&mut self, payload: Payload) -> Result<TransportFrame, ()> {
        // Increase nonce. WARNING: Re-used nonces lead to catastrophic
        // crypto failure. Ensure this increases always.
        self.send_nonce += 1;

        let encrypted_message = self.encrypt(&self.send_key, self.send_nonce, &payload);

        Ok(TransportFrame {
            payload: encrypted_message.into(),
            nonce: self.send_nonce,
        })
    }

    /// Decrypts the transport frame, mutates the state and returns the plaintext message.
    pub(crate) fn receive(
        &mut self,
        transport_frame: &TransportFrame,
    ) -> Result<Payload, ReceiveError> {
        if transport_frame.nonce > self.receive_nonce {
            if let Ok(plaintext) = self.try_decrypt(&self.receive_key, transport_frame) {
                self.receive_nonce = transport_frame.nonce;
                Ok(Payload(plaintext))
            } else {
                warn!("Failed to decrypt incoming IPC message");
                Err(ReceiveError::Decryption)
            }
        } else {
            warn!("Ipc message was replayed! Discarding...");
            Err(ReceiveError::NonceReplay)
        }
    }

    fn encrypt(&self, key: &SymmetricKey, nonce: u64, payload: &Payload) -> Vec<u8> {
        let mut buffer = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let cipher = get_cipher_with_key(key, &self.transport_cipher);
        let len = cipher.encrypt(nonce, &[], payload.as_ref(), &mut buffer);
        buffer.truncate(len);
        buffer
    }

    fn try_decrypt(
        &self,
        key: &SymmetricKey,
        transport_message: &TransportFrame,
    ) -> Result<Vec<u8>, ()> {
        let mut buffer = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let cipher = get_cipher_with_key(key, &self.transport_cipher);
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
}

/// Returns the current time as seconds since the Unix epoch.
pub(crate) fn current_epoch_secs() -> u64 {
    #[cfg(feature = "wasm")]
    {
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .expect("System clock is before Unix epoch")
            .as_secs()
    }
    #[cfg(not(feature = "wasm"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System clock is before Unix epoch")
            .as_secs()
    }
}

fn get_cipher_with_key(
    key: &SymmetricKey,
    cipher: &TransportCipher,
) -> Box<dyn snow::types::Cipher> {
    let resolver = DefaultResolver;
    let snow_cipher = match cipher {
        TransportCipher::ChaCha20Poly1305 => &snow::params::CipherChoice::ChaChaPoly,
        TransportCipher::Aes256Gcm => &snow::params::CipherChoice::AESGCM,
    };
    let mut cipher = resolver
        .resolve_cipher(snow_cipher)
        .expect("Cipher should be supported by the resolver");
    cipher.set(&key.0);
    cipher
}

/// Wire format — always encrypted with current symmetric keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TransportFrame {
    pub(crate) payload: ByteBuf,
    pub(crate) nonce: u64,
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
mod tests {
    use super::*;

    fn test_keys() -> (SymmetricKey, SymmetricKey) {
        let send_key = SymmetricKey([1u8; KEY_SIZE]);
        let receive_key = SymmetricKey([2u8; KEY_SIZE]);
        (send_key, receive_key)
    }

    fn make_pair() -> (PersistentTransportState, PersistentTransportState) {
        let (send_key, receive_key) = test_keys();
        let sender = PersistentTransportState::new(
            send_key.clone(),
            receive_key.clone(),
            TransportCipher::default(),
        );
        let receiver =
            PersistentTransportState::new(receive_key, send_key, TransportCipher::default());
        (sender, receiver)
    }

    #[test]
    fn test_send_and_receive_payload() {
        let (mut sender, mut receiver) = make_pair();

        let payload: Payload = b"ping".to_vec().into();
        let frame = sender.send(payload).expect("send should succeed");
        let received = receiver.receive(&frame).expect("receive should succeed");

        assert_eq!(received.as_ref(), b"ping");
    }

    #[test]
    fn test_send_and_receive_multiple_messages() {
        let (mut sender, mut receiver) = make_pair();

        for i in 0..5 {
            let payload: Payload = format!("msg-{i}").into_bytes().into();
            let frame = sender.send(payload).expect("send should succeed");
            let received = receiver.receive(&frame).expect("receive should succeed");
            assert_eq!(received.as_ref(), format!("msg-{i}").as_bytes());
        }
    }

    #[test]
    fn test_nonce_replay_is_rejected() {
        let (mut sender, mut receiver) = make_pair();

        let payload: Payload = b"first".to_vec().into();
        let frame = sender.send(payload).expect("send should succeed");

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
        let msg1: Payload = b"first".to_vec().into();
        let msg2: Payload = b"second".to_vec().into();
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

        let payload: Payload = b"important".to_vec().into();
        let mut frame = sender.send(payload).expect("send should succeed");

        // Tamper with the ciphertext
        frame.payload[0] ^= 0xFF;

        let result = receiver.receive(&frame);
        assert!(result.is_err(), "tampered ciphertext must fail decryption");
    }

    #[test]
    fn test_is_older_than_returns_false_when_younger_than_threshold() {
        let (mut state, _) = make_pair();
        state.set_last_handshake_epoch_secs_for_test(100);

        let is_expired = state.is_older_than(150, 60);
        assert!(!is_expired, "session newer than threshold must not expire");
    }

    #[test]
    fn test_is_older_than_returns_false_when_equal_to_threshold() {
        let (mut state, _) = make_pair();
        state.set_last_handshake_epoch_secs_for_test(100);

        let is_expired = state.is_older_than(160, 60);
        assert!(!is_expired, "session equal to threshold must not expire");
    }

    #[test]
    fn test_is_older_than_returns_true_when_older_than_threshold() {
        let (mut state, _) = make_pair();
        state.set_last_handshake_epoch_secs_for_test(100);

        let is_expired = state.is_older_than(161, 60);
        assert!(is_expired, "session older than threshold must expire");
    }

    #[test]
    fn test_is_older_than_handles_clock_rollback_with_saturating_subtraction() {
        let (mut state, _) = make_pair();
        state.set_last_handshake_epoch_secs_for_test(200);

        let is_expired = state.is_older_than(100, 60);
        assert!(
            !is_expired,
            "clock rollback should not underflow or force expiry"
        );
    }
}
