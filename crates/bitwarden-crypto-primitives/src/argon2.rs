//! Argon2id, version 0x13 (RFC 9106).

use crate::{Error, backend};

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Passes over memory.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

/// Derives `out.len()` bytes from `password` and `salt`.
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    params: &Params,
    out: &mut [u8],
) -> Result<(), Error> {
    backend::argon2::argon2id(password, salt, params, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer() {
        // Reference:
        // $argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc
        let params = Params {
            memory_kib: 65536,
            iterations: 2,
            parallelism: 1,
        };
        let mut out = [0u8; 32];
        argon2id(b"password", b"somesalt", &params, &mut out).expect("valid params");
        assert_eq!(
            hex::encode(out),
            "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
        );
    }

    #[test]
    fn rejects_invalid_params() {
        let params = Params {
            memory_kib: 1,
            iterations: 0,
            parallelism: 0,
        };
        let mut out = [0u8; 32];
        assert_eq!(
            argon2id(b"password", b"somesalt", &params, &mut out),
            Err(Error::InvalidParameters)
        );
    }
}
