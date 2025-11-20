#![doc = include_str!("../README.md")]

/// Error types for the Noise Protocol implementation
pub mod error;

use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, TransportState};

#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::error::NoiseProtocolError;

// Noise patterns
const NOISE_PATTERN_XX: &str = "Noise_XX_25519_AESGCM_SHA256";
const NOISE_PATTERN_XXPSK3: &str = "Noise_XXpsk3_25519_AESGCM_SHA256";

/// Keypair structure
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Keypair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl Keypair {
    // New keypair
    #[allow(missing_docs)]
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Keypair {
        Keypair {
            public_key,
            secret_key,
        }
    }

    // Public key
    #[allow(missing_docs)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    // Private key
    #[allow(missing_docs)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
}

/// Generate a new Curve25519 keypair
pub fn generate_keypair() -> Result<Keypair, NoiseProtocolError> {
    let builder = Builder::new(
        NOISE_PATTERN_XX
            .parse()
            .map_err(|_| NoiseProtocolError::NoisePatternParse)?,
    );

    let keypair = builder
        .generate_keypair()
        .map_err(|_| NoiseProtocolError::KeypairGeneration)?;

    Ok(Keypair {
        public_key: keypair.public.to_vec(),
        secret_key: keypair.private.to_vec(),
    })
}

/// Noise Protocol state machine
#[allow(dead_code)]
pub struct NoiseProtocol {
    handshake: Option<HandshakeState>,
    transport: Option<TransportState>,
    is_initiator: bool,
    handshake_complete: bool,
}

impl NoiseProtocol {
    /// Create a new Noise protocol instance
    ///
    /// # Arguments
    /// * `is_initiator` - Whether this is the initiator (true) or responder (false)
    /// * `static_keypair` - Optional static keypair (if None, generates new one)
    /// * `psk` - Optional pre-shared key for additional authentication
    pub fn new(
        is_initiator: bool,
        static_secret_key: Option<Vec<u8>>,
        psk: Option<Vec<u8>>,
    ) -> Result<NoiseProtocol, NoiseProtocolError> {
        // Choose pattern based on whether PSK is provided
        let pattern = if psk.is_some() {
            NOISE_PATTERN_XXPSK3
        } else {
            NOISE_PATTERN_XX
        };

        let mut builder = Builder::new(
            pattern
                .parse()
                .map_err(|_| NoiseProtocolError::NoisePatternParse)?,
        );

        // Store keys to keep them alive for the builder
        let secret_key: Vec<u8>;

        // Set static keypair
        if let Some(secret) = static_secret_key {
            if secret.len() != 32 {
                return Err(NoiseProtocolError::StaticSecretKeyLength);
            }
            secret_key = secret;
            builder = builder.local_private_key(&secret_key);
        } else {
            let keypair = builder
                .generate_keypair()
                .map_err(|_| NoiseProtocolError::KeypairGeneration)?;
            secret_key = keypair.private.to_vec();
            builder = builder.local_private_key(&secret_key);
        }

        // Set PSK if provided
        let psk_data = psk;
        if let Some(ref psk_bytes) = psk_data {
            if psk_bytes.len() != 32 {
                return Err(NoiseProtocolError::BadPskLength);
            }
            builder = builder.psk(3, psk_bytes); // psk3 - PSK on 3rd message
        }

        // Build handshake state
        let handshake = if is_initiator {
            builder
                .build_initiator()
                .map_err(|_| NoiseProtocolError::Initiator)?
        } else {
            builder
                .build_responder()
                .map_err(|_| NoiseProtocolError::Responder)?
        };

        Ok(NoiseProtocol {
            handshake: Some(handshake),
            transport: None,
            is_initiator,
            handshake_complete: false,
        })
    }

    /// Write a handshake message
    /// Returns the message to send to the peer
    pub fn write_message(&mut self, payload: Option<Vec<u8>>) -> Result<Vec<u8>, NoiseProtocolError> {
        if self.handshake_complete {
            return Err(NoiseProtocolError::UseEncryptInstead);
        }

        let handshake = self
            .handshake
            .as_mut()
            .ok_or(NoiseProtocolError::HandshakeNotInitialized)?;

        let payload_bytes = payload.unwrap_or_default();
        let mut buf = vec![0u8; 65535]; // Max Noise message size

        let len = handshake
            .write_message(&payload_bytes, &mut buf)
            .map_err(|_| NoiseProtocolError::HandshakeWriteError)?;

        buf.truncate(len);

        Ok(buf)
    }

    /// Read a handshake message from the peer
    /// Returns the payload contained in the message
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseProtocolError> {
        if self.handshake_complete {
            return Err(NoiseProtocolError::UseDecryptInstead);
        }

        let handshake = self
            .handshake
            .as_mut()
            .ok_or(NoiseProtocolError::HandshakeNotInitialized)?;

        let mut buf = vec![0u8; 65535];

        let len = handshake
            .read_message(message, &mut buf)
            .map_err(|_| NoiseProtocolError::HandshakeReadError)?;

        buf.truncate(len);

        Ok(buf)
    }

    /// Complete the handshake and derive transport keys
    pub fn split(&mut self) -> Result<(), NoiseProtocolError> {
        if self.handshake_complete {
            return Err(NoiseProtocolError::HandshakeAlreadyComplete);
        }

        let handshake = self
            .handshake
            .take()
            .ok_or(NoiseProtocolError::HandshakeNotInitialized)?;

        let transport = handshake
            .into_transport_mode()
            .map_err(|_| NoiseProtocolError::HandshakeSplit)?;

        self.transport = Some(transport);
        self.handshake_complete = true;

        Ok(())
    }

    /// Encrypt a message (after handshake is complete)
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseProtocolError> {
        if !self.handshake_complete {
            return Err(NoiseProtocolError::HandshakeNotComplete);
        }

        let transport = self
            .transport
            .as_mut()
            .ok_or(NoiseProtocolError::TransportNotInitialized)?;

        let mut buf = vec![0u8; 65535];

        let len = transport
            .write_message(plaintext, &mut buf)
            .map_err(|_| NoiseProtocolError::EncryptionFailed)?;

        buf.truncate(len);

        Ok(buf)
    }

    /// Decrypt a message (after handshake is complete)
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseProtocolError> {
        if !self.handshake_complete {
            return Err(NoiseProtocolError::HandshakeNotComplete);
        }

        let transport = self
            .transport
            .as_mut()
            .ok_or(NoiseProtocolError::TransportNotInitialized)?;

        let mut buf = vec![0u8; 65535];

        let len = transport
            .read_message(ciphertext, &mut buf)
            .map_err(|_| NoiseProtocolError::DecryptionFailed)?;

        buf.truncate(len);

        Ok(buf)
    }

    /// Check if handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Get the remote static public key (available after handshake)
    pub fn get_remote_static_public_key(&self) -> Result<Vec<u8>, NoiseProtocolError> {
        if !self.handshake_complete {
            return Err(NoiseProtocolError::HandshakeNotComplete);
        }

        // Note: snow doesn't expose remote static key directly after transport mode
        // This would need to be stored during handshake if needed
        Err(NoiseProtocolError::RemoteStaticKeyNotAvailable)
    }
}
