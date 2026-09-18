//! Names of the Chrome DevTools performance tracks this crate draws on.
//!
//! ```text
//!   ── Slow Crypto ──────────────────────────────
//!       Argon2id    ▉▉▉▉▉▉▉▉▉▉▉▉▉            ◀ one entry per derivation
//!       PBKDF2      ▉▉▉▉▉
//!       RSA                      ▉▉▉▉▉▉      ◀ keygen, encrypt, decrypt
//!       Ed25519                        ▉     ◀ keygen, sign, verify
//!       ML-DSA-44                       ▉▉
//! ```
//!
//! Only operations that are slow by construction are recorded: password-based key derivation, and
//! the asymmetric primitives, whose cost is set by the algorithm rather than by the size of the
//! data. Symmetric encryption is left out because many tiny operations would cause significant
//! slowness.

/// Track group holding the deliberately expensive crypto operations.
pub(crate) const GROUP: &str = "Slow Crypto";

/// Argon2id derivations.
pub(crate) const ARGON2_TRACK: &str = "Argon2id";

/// PBKDF2 derivations.
pub(crate) const PBKDF2_TRACK: &str = "PBKDF2";

/// RSA-2048 key generation, encryption and decryption.
pub(crate) const RSA_TRACK: &str = "RSA";

/// Ed25519 key generation, signing and verification.
pub(crate) const ED25519_TRACK: &str = "Ed25519";

/// ML-DSA-44 key generation, signing and verification.
pub(crate) const ML_DSA_TRACK: &str = "ML-DSA-44";
