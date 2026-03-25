//! This module implements the crypto provided on the basis of the noise protocol
//! framework. Please note that either side may loose state due to "process reload".
//! Because of this, it is accepted that a new handshake is done. Security is provided
//! against passive attackers both of the traffic, and subsequent key compromise, but
//! active attacks are not protected against.

pub(super) const NOISE_MAX_MESSAGE_LEN: usize = 65535;

pub mod crypto_provider;
pub(super) mod handshake;
mod transport_state;
