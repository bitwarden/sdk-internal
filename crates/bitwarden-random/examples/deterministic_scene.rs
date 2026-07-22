//! Demonstrates deterministic, reproducible randomness for tests via the
//! `dangerous-seeded-rng-for-testing` feature.
//!
//! Run with:
//! `cargo run --example deterministic_scene -p bitwarden-random --features
//! dangerous-seeded-rng-for-testing`

#[cfg(feature = "dangerous-seeded-rng-for-testing")]
fn main() {
    use bitwarden_random::{Scene, clear_seed, rng, rng_set_scene, set_seed_raw};
    use rand::RngExt;

    // Selecting a scene makes every subsequent `rng()` on this thread deterministic.
    rng_set_scene(Scene::SceneA);
    let first: [u8; 8] = rng().random();

    // Re-selecting the same scene reproduces the exact same stream.
    rng_set_scene(Scene::SceneA);
    let again: [u8; 8] = rng().random();
    assert_eq!(first, again);

    // A different scene maps to a different seed, and hence a different stream.
    rng_set_scene(Scene::SceneB);
    let other: [u8; 8] = rng().random();
    assert_ne!(first, other);

    // For full control, seed with raw bytes directly.
    set_seed_raw([42u8; 32]);
    let _raw: [u8; 8] = rng().random();

    // Revert to the OS entropy source when done.
    clear_seed();
}

#[cfg(not(feature = "dangerous-seeded-rng-for-testing"))]
fn main() {
    // This example only does something with the `dangerous-seeded-rng-for-testing` feature enabled.
}
