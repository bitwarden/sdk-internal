#![doc = include_str!("../README.md")]

use snow::{Builder, HandshakeState, TransportState};
use wasm_bindgen::prelude::*;
use web_sys::console;

// Noise patterns
const NOISE_PATTERN_XX: &str = "Noise_XX_25519_AESGCM_SHA256";
const NOISE_PATTERN_XXPSK3: &str = "Noise_XXpsk3_25519_AESGCM_SHA256";

/// Log to browser console
fn log(msg: &str) {
    console::log_1(&JsValue::from_str(msg));
}

/// Keypair structure
#[wasm_bindgen]
pub struct Keypair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl Keypair {
    // New keypair
    #[allow(missing_docs)]
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Keypair {
        Keypair {
            public_key,
            secret_key,
        }
    }

    // Public key
    #[wasm_bindgen(getter)]
    #[allow(missing_docs)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    // Private key
    #[wasm_bindgen(getter)]
    #[allow(missing_docs)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
}

/// Generate a new Curve25519 keypair
#[wasm_bindgen]
pub fn generate_keypair() -> Result<Keypair, JsValue> {
    let builder = Builder::new(
        NOISE_PATTERN_XX
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Failed to parse pattern: {}", e)))?,
    );

    let keypair = builder
        .generate_keypair()
        .map_err(|e| JsValue::from_str(&format!("Failed to generate keypair: {}", e)))?;

    log("Generated new Curve25519 keypair");

    Ok(Keypair {
        public_key: keypair.public.to_vec(),
        secret_key: keypair.private.to_vec(),
    })
}

/// Noise Protocol state machine
#[wasm_bindgen]
#[allow(dead_code)]
pub struct NoiseProtocol {
    handshake: Option<HandshakeState>,
    transport: Option<TransportState>,
    is_initiator: bool,
    handshake_complete: bool,
}

#[wasm_bindgen]
impl NoiseProtocol {
    /// Create a new Noise protocol instance
    ///
    /// # Arguments
    /// * `is_initiator` - Whether this is the initiator (true) or responder (false)
    /// * `static_keypair` - Optional static keypair (if None, generates new one)
    /// * `psk` - Optional pre-shared key for additional authentication
    #[wasm_bindgen(constructor)]
    pub fn new(
        is_initiator: bool,
        static_secret_key: Option<Vec<u8>>,
        psk: Option<Vec<u8>>,
    ) -> Result<NoiseProtocol, JsValue> {
        // Choose pattern based on whether PSK is provided
        let pattern = if psk.is_some() {
            NOISE_PATTERN_XXPSK3
        } else {
            NOISE_PATTERN_XX
        };

        let mut builder = Builder::new(
            pattern
                .parse()
                .map_err(|e| JsValue::from_str(&format!("Failed to parse pattern: {}", e)))?,
        );

        // Store keys to keep them alive for the builder
        let secret_key: Vec<u8>;

        // Set static keypair
        if let Some(secret) = static_secret_key {
            if secret.len() != 32 {
                return Err(JsValue::from_str("Static secret key must be 32 bytes"));
            }
            secret_key = secret;
            builder = builder.local_private_key(&secret_key);
            log(&format!(
                "Using provided static keypair ({})",
                if is_initiator {
                    "initiator"
                } else {
                    "responder"
                }
            ));
        } else {
            let keypair = builder
                .generate_keypair()
                .map_err(|e| JsValue::from_str(&format!("Failed to generate keypair: {}", e)))?;
            secret_key = keypair.private.to_vec();
            builder = builder.local_private_key(&secret_key);
            log(&format!(
                "Generated new static keypair ({})",
                if is_initiator {
                    "initiator"
                } else {
                    "responder"
                }
            ));
        }

        // Set PSK if provided
        let psk_data = psk;
        if let Some(ref psk_bytes) = psk_data {
            if psk_bytes.len() != 32 {
                return Err(JsValue::from_str("PSK must be 32 bytes"));
            }
            builder = builder.psk(3, psk_bytes); // psk3 - PSK on 3rd message
            log("PSK configured for handshake");
        }

        // Build handshake state
        let handshake = if is_initiator {
            builder
                .build_initiator()
                .map_err(|e| JsValue::from_str(&format!("Failed to build initiator: {}", e)))?
        } else {
            builder
                .build_responder()
                .map_err(|e| JsValue::from_str(&format!("Failed to build responder: {}", e)))?
        };

        log(&format!(
            "Noise {} handshake initialized ({})",
            if psk_data.is_some() { "XXpsk3" } else { "XX" },
            if is_initiator {
                "initiator"
            } else {
                "responder"
            }
        ));

        Ok(NoiseProtocol {
            handshake: Some(handshake),
            transport: None,
            is_initiator,
            handshake_complete: false,
        })
    }

    /// Write a handshake message
    /// Returns the message to send to the peer
    #[wasm_bindgen(js_name = writeMessage)]
    pub fn write_message(&mut self, payload: Option<Vec<u8>>) -> Result<Vec<u8>, JsValue> {
        if self.handshake_complete {
            return Err(JsValue::from_str(
                "Handshake already complete, use encrypt() instead",
            ));
        }

        let handshake = self
            .handshake
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Handshake not initialized"))?;

        let payload_bytes = payload.unwrap_or_default();
        let mut buf = vec![0u8; 65535]; // Max Noise message size

        let len = handshake
            .write_message(&payload_bytes, &mut buf)
            .map_err(|e| JsValue::from_str(&format!("Failed to write message: {}", e)))?;

        buf.truncate(len);
        log(&format!("Sent handshake message (len: {})", len));

        Ok(buf)
    }

    /// Read a handshake message from the peer
    /// Returns the payload contained in the message
    #[wasm_bindgen(js_name = readMessage)]
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        if self.handshake_complete {
            return Err(JsValue::from_str(
                "Handshake already complete, use decrypt() instead",
            ));
        }

        let handshake = self
            .handshake
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Handshake not initialized"))?;

        let mut buf = vec![0u8; 65535];

        let len = handshake
            .read_message(message, &mut buf)
            .map_err(|e| JsValue::from_str(&format!("Failed to read message: {}", e)))?;

        buf.truncate(len);
        log(&format!(
            "Received handshake message (len: {}, payload: {})",
            message.len(),
            len
        ));

        Ok(buf)
    }

    /// Complete the handshake and derive transport keys
    #[wasm_bindgen]
    pub fn split(&mut self) -> Result<(), JsValue> {
        if self.handshake_complete {
            return Err(JsValue::from_str("Handshake already complete"));
        }

        let handshake = self
            .handshake
            .take()
            .ok_or_else(|| JsValue::from_str("Handshake not initialized"))?;

        let transport = handshake
            .into_transport_mode()
            .map_err(|e| JsValue::from_str(&format!("Failed to split handshake: {}", e)))?;

        self.transport = Some(transport);
        self.handshake_complete = true;
        log("Handshake complete - transport keys derived");

        Ok(())
    }

    /// Encrypt a message (after handshake is complete)
    #[wasm_bindgen(js_name = encryptMessage)]
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        if !self.handshake_complete {
            return Err(JsValue::from_str("Handshake not complete"));
        }

        let transport = self
            .transport
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Transport not initialized"))?;

        let mut buf = vec![0u8; 65535];

        let len = transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| JsValue::from_str(&format!("Failed to encrypt: {}", e)))?;

        buf.truncate(len);
        log(&format!("Message encrypted (len: {})", len));

        Ok(buf)
    }

    /// Decrypt a message (after handshake is complete)
    #[wasm_bindgen(js_name = decryptMessage)]
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
        if !self.handshake_complete {
            return Err(JsValue::from_str("Handshake not complete"));
        }

        let transport = self
            .transport
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Transport not initialized"))?;

        let mut buf = vec![0u8; 65535];

        let len = transport
            .read_message(ciphertext, &mut buf)
            .map_err(|e| JsValue::from_str(&format!("Failed to decrypt: {}", e)))?;

        buf.truncate(len);
        log(&format!("Message decrypted (len: {})", len));

        Ok(buf)
    }

    /// Check if handshake is complete
    #[wasm_bindgen(js_name = isHandshakeComplete)]
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Get the remote static public key (available after handshake)
    #[wasm_bindgen(js_name = getRemoteStaticPublicKey)]
    pub fn get_remote_static_public_key(&self) -> Result<Vec<u8>, JsValue> {
        if !self.handshake_complete {
            return Err(JsValue::from_str("Handshake not complete"));
        }

        // Note: snow doesn't expose remote static key directly after transport mode
        // This would need to be stored during handshake if needed
        Err(JsValue::from_str(
            "Remote static key not available after split",
        ))
    }
}

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    console::log_1(&JsValue::from_str("Rust Noise WASM module initialized"));
}
