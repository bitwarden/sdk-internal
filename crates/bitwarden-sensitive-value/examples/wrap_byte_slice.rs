//! Demonstrates wrapping a borrowed `&[u8]` with [`SensitiveSlice`] for a zero-copy view of secret
//! bytes. Wrapping a reference borrows the underlying buffer instead of cloning it — useful when
//! the bytes already live in another owned buffer (e.g. a parsed message or a key store entry) and
//! you only need a non-logging handle to them.

use bitwarden_sensitive_value::{ExposeSensitive, SensitiveSlice};

fn main() {
    // Pretend this buffer came from somewhere we don't want to copy out of — a network frame,
    // a memory-mapped file, a decrypted scratch buffer, etc.
    let key_material: [u8; 32] = [0x42; 32];

    // Wrap a borrow. This is a zero-copy operation with redacted `Debug`/`Display`.
    let secret: SensitiveSlice<'_> = SensitiveSlice::from(key_material.as_slice());
    #[cfg(not(feature = "dangerous-crypto-debug"))]
    assert_eq!(format!("{secret:?}"), "[REDACTED]");

    // The borrow is tied to `key_material`'s lifetime — the wrapper does not extend it.
    derive_subkey(secret.expose());

    // The owner still has the underlying buffer and can wrap it again as needed.
    assert_eq!(key_material.len(), 32);
}

fn derive_subkey(secret: &[u8]) {
    assert_eq!(secret.len(), 32);
    assert!(secret.iter().all(|&b| b == 0x42));
}
