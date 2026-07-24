//! Deterministic, seeded RNG support for tests/benches.

use rand::SeedableRng;

thread_local! {
    /// When `Some`, [`crate::rng`] returns a handle that advances this single stream across all
    /// `rng()` calls on the thread (keeping IVs/nonces unique while reproducible).
    static SEEDED_STREAM: core::cell::RefCell<Option<rand_chacha::ChaCha8Rng>> =
        const { core::cell::RefCell::new(None) };
}

/// Sets up a deterministic, seeded ChaCha8 stream for the current thread.
/// Where possible, the higher level [`rng_set_scene`] should be used instead.
pub fn set_seed_raw(seed: [u8; 32]) {
    SEEDED_STREAM.with(|c| *c.borrow_mut() = Some(rand_chacha::ChaCha8Rng::from_seed(seed)));
}

/// A named, reproducible RNG scene for tests. Each variant maps to a fixed seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scene {
    /// Deterministic scene A.
    SceneA,
    /// Deterministic scene B.
    SceneB,
    /// Deterministic scene C.
    SceneC,
}

/// Seeds the current thread's RNG with the deterministic seed for the given [`Scene`].
///
/// The scene is mapped to a number which is used as the seed (via [`set_seed_raw`]).
pub fn rng_set_scene(scene: Scene) {
    set_seed_raw([scene as u8; 32]);
}

/// Removes any thread-local seed, reverting [`crate::rng`] to the OS entropy source on this thread.
pub fn clear_seed() {
    SEEDED_STREAM.with(|c| *c.borrow_mut() = None);
}

pub(crate) fn is_seeded() -> bool {
    SEEDED_STREAM.with(|c| c.borrow().is_some())
}

pub(crate) fn next_u32() -> u32 {
    SEEDED_STREAM
        .with(|c| rand::Rng::next_u32(c.borrow_mut().as_mut().expect("seed set for this thread")))
}

pub(crate) fn next_u64() -> u64 {
    SEEDED_STREAM
        .with(|c| rand::Rng::next_u64(c.borrow_mut().as_mut().expect("seed set for this thread")))
}

pub(crate) fn fill_bytes(dst: &mut [u8]) {
    SEEDED_STREAM.with(|c| {
        rand::Rng::fill_bytes(
            c.borrow_mut().as_mut().expect("seed set for this thread"),
            dst,
        )
    });
}

#[cfg(test)]
mod tests {
    use rand::RngExt;

    use super::*;
    use crate::rng;

    #[test]
    fn set_seed_makes_rng_calls_deterministic_and_advancing() {
        // Two separate `rng()` calls draw from the SAME advancing stream — distinct values...
        set_seed_raw([7u8; 32]);
        let a: [u8; 16] = rng().random();
        let b: [u8; 16] = rng().random();
        assert_ne!(a, b, "successive rng() must not repeat (no IV/nonce reuse)");

        // ...and re-seeding reproduces the exact sequence.
        set_seed_raw([7u8; 32]);
        let a2: [u8; 16] = rng().random();
        let b2: [u8; 16] = rng().random();
        assert_eq!((a, b), (a2, b2));

        clear_seed();
    }

    #[test]
    fn rng_set_scene_is_deterministic_and_distinct_per_scene() {
        rng_set_scene(Scene::SceneA);
        let a1: [u8; 16] = rng().random();
        rng_set_scene(Scene::SceneA);
        let a2: [u8; 16] = rng().random();
        assert_eq!(a1, a2, "same scene must reproduce the same stream");

        rng_set_scene(Scene::SceneB);
        let b: [u8; 16] = rng().random();
        assert_ne!(a1, b, "different scenes must use different seeds");

        clear_seed();
    }
}
