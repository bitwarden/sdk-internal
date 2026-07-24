#![doc = include_str!("../README.md")]

use std::convert::Infallible;

use rand::TryRng;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod ffi;
pub use ffi::{GenBytesError, GenRangeError, SdkRandomNumberClient};

#[cfg(feature = "dangerous-seeded-rng-for-testing")]
mod seeded;
#[cfg(feature = "dangerous-seeded-rng-for-testing")]
pub use seeded::{Scene, clear_seed, rng_set_scene, set_seed_raw};

#[cfg(feature = "snow")]
mod snow_resolver;
#[cfg(feature = "snow")]
pub use snow_resolver::SdkCryptoResolver;

/// Marker trait for random number generators usable within the Bitwarden SDK.
///
/// Supertrait of [`rand::CryptoRng`] (hence also [`rand::Rng`] / [`rand::RngExt`]) and additionally
/// requires `Send + Sync`, so any `SdkRng` is a drop-in wherever the SDK or third-party crates
/// expect a cryptographically secure, thread-safe RNG.
pub trait SdkRng: rand::CryptoRng + Send + Sync {}

impl<T: rand::CryptoRng + Send + Sync + ?Sized> SdkRng for T {}

/// The default Bitwarden RNG.
#[derive(Clone, Debug)]
pub struct SdkRngImpl(Inner);

#[derive(Clone, Debug)]
enum Inner {
    /// OS entropy source.
    Os,
    /// Draws from the thread-local stream installed by [`set_seed_raw`]. Carries no data, so the
    /// struct stays `Send + Sync`.
    #[cfg(feature = "dangerous-seeded-rng-for-testing")]
    Seeded,
}

impl Default for SdkRngImpl {
    fn default() -> Self {
        Self(Inner::Os)
    }
}

impl SdkRngImpl {
    /// Creates a new OS-backed RNG.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Returns an [`SdkRngImpl`]. Mirrors [`rand::rng`] for ergonomic drop-in replacement.
pub fn rng() -> SdkRngImpl {
    #[cfg(feature = "dangerous-seeded-rng-for-testing")]
    if seeded::is_seeded() {
        return SdkRngImpl(Inner::Seeded);
    }
    SdkRngImpl::default()
}

impl TryRng for SdkRngImpl {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        match &self.0 {
            Inner::Os => Ok(rand::rngs::SysRng
                .try_next_u32()
                .expect("system RNG must not fail")),
            #[cfg(feature = "dangerous-seeded-rng-for-testing")]
            Inner::Seeded => Ok(seeded::next_u32()),
        }
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        match &self.0 {
            Inner::Os => Ok(rand::rngs::SysRng
                .try_next_u64()
                .expect("system RNG must not fail")),
            #[cfg(feature = "dangerous-seeded-rng-for-testing")]
            Inner::Seeded => Ok(seeded::next_u64()),
        }
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        match &self.0 {
            Inner::Os => rand::rngs::SysRng
                .try_fill_bytes(dst)
                .expect("system RNG must not fail"),
            #[cfg(feature = "dangerous-seeded-rng-for-testing")]
            Inner::Seeded => seeded::fill_bytes(dst),
        }
        Ok(())
    }
}

impl rand::TryCryptoRng for SdkRngImpl {}

#[cfg(test)]
mod tests {
    use rand::RngExt;

    use super::*;

    // Compile-time checks: SdkRngImpl satisfies SdkRng + third-party bounds, and is Send + Sync.
    fn _assert_bounds<T: SdkRng + rand::CryptoRng + rand::Rng + Send + Sync>() {}
    const _: fn() = || _assert_bounds::<SdkRngImpl>();

    #[test]
    fn os_rng_produces_distinct_bytes() {
        let mut rng = rng();
        let a: [u8; 32] = rng.random();
        let b: [u8; 32] = rng.random();
        assert_ne!(a, b);
    }
}
