use bitwarden_noise::{
    error::NoiseProtocolError, Keypair, NoiseProtocolHandle,
};
use wasm_bindgen::prelude::*;

/// Generate a new Curve25519 keypair for use with Noise protocol
#[wasm_bindgen]
pub fn generate_keypair() -> Result<Keypair, NoiseProtocolError> {
    bitwarden_noise::generate_keypair()
}

/// Create a new Noise protocol instance and return a handle to it
///
/// # Arguments
/// * `is_initiator` - Whether this is the initiator (true) or responder (false)
/// * `static_secret_key` - Optional static secret key (if None, generates new one)
/// * `psk` - Optional pre-shared key for additional authentication
///
/// # Returns
/// A handle that can be used to reference this protocol instance in subsequent calls
#[wasm_bindgen]
pub fn create_noise_protocol(
    is_initiator: bool,
    static_secret_key: Option<Vec<u8>>,
    psk: Option<Vec<u8>>,
) -> Result<NoiseProtocolHandle, NoiseProtocolError> {
    bitwarden_noise::create_noise_protocol(is_initiator, static_secret_key, psk)
}

/// Write a handshake message
///
/// # Arguments
/// * `handle` - Handle to the protocol instance
/// * `payload` - Optional payload to include in the message
///
/// # Returns
/// The message bytes to send to the peer
#[wasm_bindgen]
pub fn noise_write_message(
    handle: NoiseProtocolHandle,
    payload: Option<Vec<u8>>,
) -> Result<Vec<u8>, NoiseProtocolError> {
    bitwarden_noise::noise_write_message(handle, payload)
}

/// Read a handshake message from the peer
///
/// # Arguments
/// * `handle` - Handle to the protocol instance
/// * `message` - The message bytes received from the peer
///
/// # Returns
/// The payload contained in the message
#[wasm_bindgen]
pub fn noise_read_message(
    handle: NoiseProtocolHandle,
    message: Vec<u8>,
) -> Result<Vec<u8>, NoiseProtocolError> {
    bitwarden_noise::noise_read_message(handle, message)
}

/// Complete the handshake and transition to transport mode
///
/// # Arguments
/// * `handle` - Handle to the protocol instance
#[wasm_bindgen]
pub fn noise_split(handle: NoiseProtocolHandle) -> Result<(), NoiseProtocolError> {
    bitwarden_noise::noise_split(handle)
}

/// Encrypt a message (after handshake is complete)
///
/// # Arguments
/// * `handle` - Handle to the protocol instance
/// * `plaintext` - The plaintext bytes to encrypt
///
/// # Returns
/// The encrypted message bytes
#[wasm_bindgen]
pub fn noise_encrypt_message(
    handle: NoiseProtocolHandle,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, NoiseProtocolError> {
    bitwarden_noise::noise_encrypt_message(handle, plaintext)
}

/// Decrypt a message (after handshake is complete)
///
/// # Arguments
/// * `handle` - Handle to the protocol instance
/// * `ciphertext` - The encrypted message bytes
///
/// # Returns
/// The decrypted plaintext bytes
#[wasm_bindgen]
pub fn noise_decrypt_message(
    handle: NoiseProtocolHandle,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, NoiseProtocolError> {
    bitwarden_noise::noise_decrypt_message(handle, ciphertext)
}

/// Check if handshake is complete
///
/// # Arguments
/// * `handle` - Handle to the protocol instance
///
/// # Returns
/// True if handshake is complete, false otherwise
#[wasm_bindgen]
pub fn noise_is_handshake_complete(
    handle: NoiseProtocolHandle,
) -> Result<bool, NoiseProtocolError> {
    bitwarden_noise::noise_is_handshake_complete(handle)
}

/// Destroy a noise protocol instance and free its resources
///
/// # Arguments
/// * `handle` - Handle to the protocol instance to destroy
#[wasm_bindgen]
pub fn destroy_noise_protocol(handle: NoiseProtocolHandle) -> Result<(), NoiseProtocolError> {
    bitwarden_noise::destroy_noise_protocol(handle)
}

