use rand::TryRng;

/// Fills `dst` from the OS CSPRNG.
pub(crate) fn fill_bytes(dst: &mut [u8]) {
    rand::rngs::SysRng
        .try_fill_bytes(dst)
        .expect("system RNG must not fail");
}
