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

    fn derive(memory_kib: u32, iterations: u32, parallelism: u32, len: usize) -> String {
        let params = Params {
            memory_kib,
            iterations,
            parallelism,
        };
        let mut out = vec![0u8; len];
        argon2id(b"password", b"somesalt", &params, &mut out).expect("valid params");
        hex::encode(out)
    }

    /// Smallest valid cost (8 KiB, one pass, one lane) and a multi-lane cost.
    #[test]
    fn known_answer_cost_bounds() {
        assert_eq!(
            derive(8, 1, 1, 32),
            "f137f8e186a403a679ccd0606e5ab5dcdafe43c1640855ac8c6e33e9bd63eeb3"
        );
        assert_eq!(
            derive(64 * 1024, 3, 4, 32),
            "661fefbd6f29bcbc8f4646abc32a9d7a4645bb5c059537f8a5587f31adbecccd"
        );
    }

    /// Shortest (4 bytes) and a longer than one Blake2b block (64 bytes) tag.
    #[test]
    fn known_answer_output_lengths() {
        assert_eq!(derive(1024, 2, 1, 4), "6eafeb38");
        assert_eq!(
            derive(1024, 2, 1, 64),
            "3f1e8d2fa34c480ae2613ad1f4a8ffb54c724e1ebe8fc2a1394590bce1921c59\
            7e6158ea138c2de50d4b5c9523810a026ad8952eaa661f61c758fc6f9fabb713"
        );
    }
}
