//! This module implements the crypto provided on the basis of the noise protocol
//! framework. Please note that either side may loose state due to "process reload".
//! Because of this, it is accepted that a new handshake is done. Security is provided
//! against passive attackers both of the traffic, and subsequent key compromise, but
//! active attacks are not protected against.
//!
//! Security Definition SD1:
//! - Attacker Model:
//!   - Attacker has full passive read access to the entire IPC conversation
//! - Security Goal:
//!   - Attacker should not be able to derive any information about the plaintext messages beyond
//!   length and timing.
//!
//! Security Definition SD2:
//! - Attacker Model:
//!   - Attacker has full passive read access to the entire IPC conversation and access to the
//!     session
//!   state of one side at time X
//! Security Goal:
//! - Attacker should only be able to decrypt messages that were received or sent within the
//!   re-handshake interval

// Ref: http://noiseprotocol.org/noise.html#message-format
const NOISE_MAX_MESSAGE_LEN: usize = 65535;

pub mod crypto_provider;
pub(super) mod handshake;
mod transport_state;
