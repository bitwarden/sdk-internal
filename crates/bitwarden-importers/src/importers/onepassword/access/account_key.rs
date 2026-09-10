//! Account Key (Secret Key): A2/A3 parse, HKDF-SHA256 hash, and XOR combine.

use zeroize::Zeroize;

use super::{error::OnePasswordError, kdf};

/// The characters an Account Key is written in: base32 without the confusable `0`, `1`, `I`, `L`,
/// `O` and `U`. Everything else in the input is dropped, including the dashes.
const ALPHABET: &str = "23456789ABCDEFGHJKLMNPQRSTVWXYZ";

/// A parsed 1Password Account Key (also called the Secret Key), split into its format, uuid, and
/// key.
pub(super) struct AccountKey {
    pub format: String,
    pub uuid: String,
    pub key: String,
}

impl Drop for AccountKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl AccountKey {
    /// Parses a key string such as `A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9`, splitting it into
    /// `format` (2), `uuid` (6), and `key` (the rest).
    ///
    /// The web client's `SecretKey.fromInput` uppercases and then drops every character outside
    /// [`ALPHABET`], so dashes, whitespace and anything else a paste drags along are all forgiven.
    pub(super) fn parse(input: &str) -> Result<AccountKey, OnePasswordError> {
        let s: String = input
            .to_uppercase()
            .chars()
            .filter(|c| ALPHABET.contains(*c))
            .collect();

        let Some(format) = s.get(..2) else {
            return Err(OnePasswordError::Internal(format!(
                "invalid account key: too short, got {}",
                s.len()
            )));
        };

        // Only A3 has ever been seen on a real account. A2 comes from reverse-engineered code and
        // is untested against anything, so treat its 33-byte length as unverified.
        match format {
            "A2" if s.len() == 33 => {}
            "A3" if s.len() == 34 => {}
            "A2" => {
                return Err(OnePasswordError::Internal(format!(
                    "invalid account key: 'A2' needs 33 characters without dashes, got {}",
                    s.len()
                )));
            }
            "A3" => {
                return Err(OnePasswordError::Internal(format!(
                    "invalid account key: 'A3' needs 34 characters without dashes, got {}",
                    s.len()
                )));
            }
            _ => {
                return Err(OnePasswordError::Internal(format!(
                    "invalid account key: unknown format '{format}'"
                )));
            }
        }

        let invalid = || OnePasswordError::Internal("invalid account key".into());
        Ok(AccountKey {
            format: format.to_string(),
            uuid: s.get(2..8).ok_or_else(invalid)?.to_string(),
            key: s.get(8..).ok_or_else(invalid)?.to_string(),
        })
    }

    /// `HKDF-SHA256(ikm = key, salt = uuid, info = format)`, 32 bytes.
    pub(super) fn hash(&self) -> [u8; 32] {
        kdf::hkdf_sha256(&self.format, self.key.as_bytes(), self.uuid.as_bytes())
    }

    /// XORs the hash with `bytes`, which must be exactly 32 bytes long.
    pub(super) fn combine_with(&self, bytes: &[u8]) -> Result<[u8; 32], OnePasswordError> {
        let mut h = self.hash();
        if h.len() != bytes.len() {
            return Err(OnePasswordError::Internal(
                "size doesn't match hash function".into(),
            ));
        }

        for (byte, other) in h.iter_mut().zip(bytes) {
            *byte ^= other;
        }

        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;

    use super::*;

    fn key() -> AccountKey {
        AccountKey {
            format: "A3".into(),
            uuid: "RTN9SA".into(),
            key: "DY9445Y5FF96X6E7B5GPFA95R9".into(),
        }
    }

    #[test]
    fn parse_returns_parsed_format_a3_key() {
        let key = AccountKey::parse("A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9").expect("valid key");
        assert_eq!(key.format, "A3");
        assert_eq!(key.uuid, "RTN9SA");
        assert_eq!(key.key, "DY9445Y5FF96X6E7B5GPFA95R9");
    }

    /// The web client drops anything outside the alphabet, so a paste that drags whitespace or
    /// stray punctuation along still parses.
    #[test]
    fn parse_ignores_everything_outside_the_alphabet() {
        let cases = [
            "  A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9\n",
            "a3-rtn9sa-dy9445y5ff96x6e7b5gpfa95r9",
            "A3 RTN9SA DY9445Y 5FF96X6 E7B5GPF A95R9",
            "A3_RTN9SA_DY9445Y5FF96X6E7B5GPFA95R9",
        ];
        for case in cases {
            let key = AccountKey::parse(case).unwrap_or_else(|e| panic!("{case:?}: {e}"));
            assert_eq!(key.format, "A3");
            assert_eq!(key.uuid, "RTN9SA");
            assert_eq!(key.key, "DY9445Y5FF96X6E7B5GPFA95R9");
        }
    }

    // Made up: no real A2 key was ever available to test against.
    #[test]
    fn parse_returns_parsed_format_a2_key() {
        let key = AccountKey::parse("A2-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R").expect("valid key");
        assert_eq!(key.format, "A2");
        assert_eq!(key.uuid, "RTN9SA");
        assert_eq!(key.key, "DY9445Y5FF96X6E7B5GPFA95R");
    }

    #[test]
    fn parse_throws_on_invalid_key_format() {
        let cases = [
            "",
            "A",
            "A2",
            "A3",
            "A2-RTN9SA-DY9445Y5FF96X6E7B5GPFA95",
            "A2-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9",
            "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R",
            "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R99",
            "A3-RTN9SA-DY9445Y-FF96X6E7B-GPFA95R9",
        ];
        for case in cases {
            match AccountKey::parse(case) {
                Ok(_) => panic!("expected {case:?} to be invalid"),
                Err(err) => assert!(
                    err.to_string().contains("invalid account key"),
                    "unexpected error for {case:?}: {err}"
                ),
            }
        }
    }

    #[test]
    fn hash_returns_hashed_key() {
        assert_eq!(
            BASE64URL_NOPAD.encode(&key().hash()),
            "ZlI2kRote1dv7uflTenyIp5jBE0u-7Fl4aIiE0D9L-g"
        );
    }

    #[test]
    fn combine_with_returns_hashed_key() {
        let combined = key()
            .combine_with(b"All your base are belong to us!!")
            .expect("32 byte input");
        assert_eq!(
            BASE64URL_NOPAD.encode(&combined),
            "Jz5asWNCDiVPjIaWKMmTUPtDZihClN8CwdZNMzWODsk"
        );
    }

    #[test]
    fn combine_with_throws_on_incorrect_length() {
        let cases: [&[u8]; 5] = [
            b"",
            b"A",
            b"All your base are belong to us",
            b"All your base are belong to us!",
            b"All your base are belong to us!!!",
        ];
        for case in cases {
            let err = key().combine_with(case).expect_err("wrong length");
            assert!(
                err.to_string().contains("hash function"),
                "unexpected error: {err}"
            );
        }
    }
}
