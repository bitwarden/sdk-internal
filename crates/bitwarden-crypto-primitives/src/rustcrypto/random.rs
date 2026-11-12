use std::convert::Infallible;

use rand::{TryCryptoRng, TryRng};

/// OS CSPRNG.
pub(crate) struct SystemRng;

impl TryRng for SystemRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand::rngs::SysRng
            .try_next_u32()
            .expect("system RNG must not fail"))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand::rngs::SysRng
            .try_next_u64()
            .expect("system RNG must not fail"))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for SystemRng {}

/// Fills `dst` from the OS CSPRNG.
pub(crate) fn fill_bytes(dst: &mut [u8]) {
    rand::rngs::SysRng
        .try_fill_bytes(dst)
        .expect("system RNG must not fail");
}
