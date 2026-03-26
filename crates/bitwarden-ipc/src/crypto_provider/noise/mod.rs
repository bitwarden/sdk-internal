//! # Noise Crypto Provider
//!
//! Implements IPC encryption using the [Noise Protocol Framework](http://noiseprotocol.org/)
//! with the NN handshake pattern. Either side may lose state due to process reload, so
//! re-handshakes are expected. Security is provided against passive attackers of both
//! traffic and subsequent key compromise, but active MITM attacks are not protected against.
//!
//! ## Protocol Flow
//!
//! ```text
//! Initiator                              Responder
//!     |                                      |
//!     |--- HandshakeStart ------------------>|
//!     |<-- HandshakeFinish ------------------|
//!     |                                      |
//!     |     [Both derive transport keys]     |
//!     |                                      |
//!     |--- TransportFrame (encrypted) ------>|
//!     |<-- TransportFrame (encrypted) -------|
//!     |              ...                     |
//!     |                                      |
//!     | [After REHANDSHAKE_INTERVAL (300s),  |
//!     |  initiator starts a new handshake]   |
//!     |                                      |
//!     |--- HandshakeStart ------------------>|
//!     |<-- HandshakeFinish ------------------|
//!     |              ...                     |
//!     |                                      |
//!     | [If responder has no session for an  |
//!     |  incoming TransportFrame, it replies |
//!     |  with CryptoInvalidated so both      |
//!     |  sides reset and re-handshake]       |
//!     |                                      |
//!     |--- TransportFrame (no session) ----->|
//!     |<-- CryptoInvalidated ----------------|
//!     |--- HandshakeStart ------------------>|
//!     |<-- HandshakeFinish ------------------|
//!     |              ...                     |
//! ```
//!
//! ## Frame Types
//!
//! All frames are CBOR-encoded [`Frame`](crypto_provider::Frame) variants sent over the
//! IPC channel:
//! - **HandshakeStart** — initiates a Noise NN handshake
//! - **HandshakeFinish** — completes the handshake
//! - **TransportFrame** — encrypted payload
//! - **CryptoInvalidated** — signals session loss so both sides reset
//!
//! ## Security Definitions
//!
//! Security Definition SD1:
//! - Attacker Model:
//!   - Attacker has full passive read access to the entire IPC conversation
//! - Security Goal:
//!   - Attacker should not be able to derive any information about the plaintext messages beyond
//!     length and timing.
//!
//! Security Definition SD2:
//! - Attacker Model:
//!   - Attacker has full passive read access to the entire IPC conversation and access to the
//!     session state of one side at time X
//! - Security Goal:
//!   - Attacker should only be able to decrypt messages that were received or sent within the
//!     re-handshake interval

// Ref: http://noiseprotocol.org/noise.html#message-format
const NOISE_MAX_MESSAGE_LEN: usize = 65535;

pub mod crypto_provider;
pub(super) mod handshake;
mod transport_state;
