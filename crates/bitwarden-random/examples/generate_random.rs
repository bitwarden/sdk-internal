//! Demonstrates the default Bitwarden SDK RNG: [`bitwarden_random::rng`] returns an OS-backed
//! generator that implements `rand::Rng` / `rand::CryptoRng`, so it is a drop-in within the `rand`
//! ecosystem.
//!
//! Run with: `cargo run --example generate_random -p bitwarden-random`

use rand::RngExt;

fn main() {
    // `rng()` mirrors `rand::rng()`. By default it draws from the operating system's CSPRNG.
    let mut rng = bitwarden_random::rng();

    // Fill a buffer with random bytes — e.g. an IV or salt.
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);

    // Generate a typed random value, and one within a range.
    let token: u64 = rng.random();
    let dice = rng.random_range(1..=6);
    assert!((1..=6).contains(&dice));

    // Two independent draws differ with overwhelming probability.
    let other_token: u64 = rng.random();
    assert_ne!(token, other_token);

    // `SdkRngImpl` is `Send + Sync` and satisfies the `SdkRng` marker trait.
    fn assert_sdk_rng<T: bitwarden_random::SdkRng>(_: &T) {}
    assert_sdk_rng(&rng);
}
