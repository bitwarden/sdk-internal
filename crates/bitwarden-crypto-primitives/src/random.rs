//! Cryptographically secure random number generation from the backend's CSPRNG.

use std::convert::Infallible;

use rand::{TryCryptoRng, TryRng};

use crate::backend;

/// The backend CSPRNG as a [`rand`] generator.
///
/// Prefer `bitwarden_random::rng()` in SDK code: it adds the test seeding hook on top of this.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRng;

impl TryRng for SystemRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        fill_bytes(&mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        fill_bytes(&mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for SystemRng {}

/// Fills `dst` with random bytes from the backend CSPRNG.
pub fn fill_bytes(dst: &mut [u8]) {
    backend::random::fill_bytes(dst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_distinct_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_bytes(&mut a);
        fill_bytes(&mut b);
        assert_ne!(a, b);
    }
}
