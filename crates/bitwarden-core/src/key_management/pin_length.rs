/// Number of characters in the account's PIN.
///
/// Stored unencrypted, so a lock screen can read it while locked, e.g. to try the PIN as soon as
/// that many characters are typed.
#[bitwarden_ffi::wasm_record]
#[derive(serde::Serialize, serde::Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[serde(transparent)]
pub struct PinLength(pub u32);

impl PinLength {
    /// The length of `pin`, in characters.
    pub fn of(pin: &str) -> Self {
        Self(pin.chars().count() as u32)
    }
}

#[cfg(feature = "wasm")]
impl TryFrom<wasm_bindgen::JsValue> for PinLength {
    type Error = serde_wasm_bindgen::Error;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        serde_wasm_bindgen::from_value(value)
    }
}

#[cfg(feature = "uniffi")]
uniffi::custom_newtype!(PinLength, u32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_characters_not_bytes() {
        assert_eq!(PinLength::of("1234"), PinLength(4));
        assert_eq!(PinLength::of("ü1"), PinLength(2));
    }

    #[test]
    fn serializes_as_a_number() {
        let serialized = serde_json::to_value(PinLength(6)).unwrap();

        assert_eq!(serialized, serde_json::json!(6));
        assert_eq!(
            serde_json::from_value::<PinLength>(serialized).unwrap(),
            PinLength(6)
        );
    }
}
