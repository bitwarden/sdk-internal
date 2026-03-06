//! This module provides an implementation based on noise for IPC encryption. The noise state needs
//! to be serializable for this. A secure channel always starts out with a transport state with
//! null-keys. Within a transport state, a re-key can happen. For this, a handshake is made, at
//! which point a new transport state is staged on both sides. Once a side receives a packet
//! encrypted for the new transport state, it can switch to it and discard the old state. This
//! allows to not have separate initial handshake and re-key operations, but to view the initial
//! handshake as a re-key from an insecure state. The initial transport state does not allow sending
//! of payload messages, but only handshake messages.

pub(super) const NOISE_MAX_MESSAGE_LEN: usize = 65535;

pub mod crypto_provider;
pub(super) mod handshake;
mod state_machine;
mod transport_state;
