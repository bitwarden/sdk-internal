//! Key management primitives owned by the KM team.
//!
//! This module hosts the [`SessionKey`] type, [`UnlockMethod`] enum, and the
//! [`PasswordManagerClient::generate_session_key`] /
//! [`PasswordManagerClient::unlock`] entry points used to rehydrate a locked
//! client into an unlocked one.

mod session_key;
mod unlock;

pub use session_key::SessionKey;
pub use unlock::{UnlockError, UnlockMethod};
