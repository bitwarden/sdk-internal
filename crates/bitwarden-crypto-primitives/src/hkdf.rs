//! HKDF-SHA256 (RFC 5869).

use zeroize::Zeroizing;

use crate::{Error, backend};

/// Pseudorandom key length in bytes (SHA-256 output).
pub const PRK_LEN: usize = 32;

/// HKDF-Extract. Returns the pseudorandom key.
pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Zeroizing<[u8; PRK_LEN]> {
    backend::hkdf::extract(salt, ikm)
}

/// HKDF-Expand of `prk` into `out`. Fails if `prk` is shorter than 32 bytes or `out` is longer
/// than 255 * 32 bytes.
pub fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    backend::hkdf::expand(prk, info, out)
}

/// HKDF-Extract followed by HKDF-Expand.
pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let prk = extract(salt, ikm);
    expand(prk.as_slice(), info, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{array, bytes};

    // RFC 5869 test case 1.
    const IKM: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    const SALT: &str = "000102030405060708090a0b0c";
    const INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
    const PRK: &str = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    const OKM: &str =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    #[test]
    fn known_answer() {
        let salt = bytes(SALT);
        let info = bytes(INFO);

        assert_eq!(
            hex::encode(extract(Some(&salt), &bytes(IKM)).as_slice()),
            PRK
        );

        let mut okm = [0u8; 42];
        derive(Some(&salt), &bytes(IKM), &info, &mut okm).expect("valid lengths");
        assert_eq!(hex::encode(okm), OKM);
    }

    #[test]
    fn rejects_short_prk_and_long_output() {
        const SHORT_PRK: &str = "00000000000000000000000000000000";
        const ZERO_PRK: &str = "0000000000000000000000000000000000000000000000000000000000000000";

        let mut out = [0u8; 32];
        assert_eq!(
            expand(&bytes(SHORT_PRK), b"", &mut out),
            Err(Error::InvalidParameters)
        );

        let mut too_long = vec![0u8; 255 * 32 + 1];
        assert_eq!(
            expand(&bytes(ZERO_PRK), b"", &mut too_long),
            Err(Error::InvalidParameters)
        );
    }

    /// RFC 5869 test case 3: no salt, no info.
    #[test]
    fn known_answer_no_salt_no_info() {
        let mut okm = [0u8; 42];
        derive(None, &bytes(IKM), b"", &mut okm).expect("valid lengths");
        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
            9d201395faa4b61a96c8"
        );
    }

    /// Shortest and longest (255 blocks) expansions; the long one is compared by its SHA-256.
    #[test]
    fn known_answer_output_length_bounds() {
        let prk: [u8; PRK_LEN] =
            array("4242424242424242424242424242424242424242424242424242424242424242");

        let mut one = [0u8; 1];
        expand(&prk, b"info", &mut one).expect("valid length");
        assert_eq!(hex::encode(one), "a2");

        let mut max = vec![0u8; 255 * PRK_LEN];
        expand(&prk, b"info", &mut max).expect("valid length");
        assert_eq!(
            hex::encode(crate::sha256::digest(&max)),
            "1a40dcf431b2fc7b6404941c3e4fcd3b1b2f9d0efb269a910fb52236ff39df59"
        );
    }
}
