use bitwarden_encoding::{B64, NotB64EncodedError};
use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

const CHALLENGE_LENGTH: usize = 32;

/// A random 32-byte value generated when a request is created and echoed in its response.
///
/// Binds a response to the request it answers. Equality is constant time. Serialized as a base64
/// string.
#[bitwarden_ffi::wasm_record]
#[derive(Clone, Serialize)]
#[serde(into = "B64")]
pub struct Challenge(#[cfg_attr(feature = "wasm", tsify(type = "string"))] [u8; CHALLENGE_LENGTH]);

impl Challenge {
    /// Generates a new random challenge.
    pub(crate) fn make() -> Self {
        let mut bytes = [0u8; CHALLENGE_LENGTH];
        bitwarden_random::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl PartialEq for Challenge {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Challenge {}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Challenge(..)")
    }
}

/// Error returned when a value isn't a base64-encoded 32-byte challenge.
#[derive(Debug, thiserror::Error)]
#[error("Invalid challenge")]
pub struct InvalidChallengeError;

impl From<NotB64EncodedError> for InvalidChallengeError {
    fn from(_: NotB64EncodedError) -> Self {
        InvalidChallengeError
    }
}

impl TryFrom<B64> for Challenge {
    type Error = InvalidChallengeError;

    fn try_from(value: B64) -> Result<Self, Self::Error> {
        let bytes: [u8; CHALLENGE_LENGTH] = value
            .as_bytes()
            .try_into()
            .map_err(|_| InvalidChallengeError)?;
        Ok(Self(bytes))
    }
}

impl From<Challenge> for B64 {
    fn from(value: Challenge) -> Self {
        B64::from(value.0.as_slice())
    }
}

impl std::str::FromStr for Challenge {
    type Err = InvalidChallengeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(B64::try_from(s)?)
    }
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        B64::from(self.clone()).fmt(f)
    }
}

impl<'de> Deserialize<'de> for Challenge {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let b64 = B64::deserialize(deserializer)?;
        Self::try_from(b64).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "uniffi")]
uniffi::custom_type!(Challenge, String, {
    try_lift: |val| bitwarden_uniffi_error::convert_result(val.parse::<Challenge>()),
    lower: |obj| obj.to_string(),
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_returns_distinct_values() {
        assert_ne!(Challenge::make(), Challenge::make());
    }

    #[test]
    fn serde_round_trip() {
        let challenge = Challenge::make();
        let json = serde_json::to_string(&challenge).unwrap();
        let restored: Challenge = serde_json::from_str(&json).unwrap();
        assert_eq!(challenge, restored);
    }

    #[test]
    fn rejects_wrong_length() {
        let short = serde_json::to_string(&B64::from([0u8; 16].as_slice())).unwrap();
        assert!(serde_json::from_str::<Challenge>(&short).is_err());
    }

    #[test]
    fn debug_hides_value() {
        assert_eq!(format!("{:?}", Challenge::make()), "Challenge(..)");
    }
}
