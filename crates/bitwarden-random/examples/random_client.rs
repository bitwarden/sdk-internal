//! Demonstrates [`bitwarden_random::SdkRandomNumberClient`], the cross-platform (WASM / UniFFI)
//! entry point for random-number generation. It is constructed and then used through
//!
//! Run with: `cargo run --example random_client -p bitwarden-random`

use bitwarden_random::{GenBytesError, SdkRandomNumberClient};

fn main() -> Result<(), GenBytesError> {
    let client = SdkRandomNumberClient::new();

    // Request cryptographically-secure random bytes — e.g. a 32-byte key or salt.
    let bytes = client.gen_bytes(32)?;
    assert_eq!(bytes.len(), 32);

    // Two independent draws differ with overwhelming probability.
    assert_ne!(client.gen_bytes(32)?, client.gen_bytes(32)?);

    // `gen_bytes` is capped at 1 KiB; requesting more returns an error. The boundary itself is
    // fine.
    assert_eq!(client.gen_bytes(1024)?.len(), 1024);
    assert!(client.gen_bytes(1025).is_err());

    // Generate a random v4 UUID, returned as a hyphenated string (as the bindings expose it).
    let uuid = client.gen_uuid();
    assert_eq!(uuid.len(), 36);
    assert_ne!(client.gen_uuid(), client.gen_uuid());

    Ok(())
}
