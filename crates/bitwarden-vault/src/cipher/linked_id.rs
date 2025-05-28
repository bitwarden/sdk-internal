use bitwarden_core::MissingFieldError;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(untagged)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum LinkedIdType {
    Login(LoginLinkedIdType),
    Card(CardLinkedIdType),
    Identity(IdentityLinkedIdType),
}

#[cfg(feature = "uniffi")]
uniffi::custom_type!(LinkedIdType, u32);

impl From<LinkedIdType> for u32 {
    fn from(v: LinkedIdType) -> Self {
        serde_json::to_value(v)
            .expect("LinkedIdType should be serializable")
            .as_u64()
            .expect("Not a numeric enum value") as u32
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr, Debug)]
#[repr(u16)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum LoginLinkedIdType {
    Username = 100,
    Password = 101,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr, Debug)]
#[repr(u16)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum CardLinkedIdType {
    CardholderName = 300,
    ExpMonth = 301,
    ExpYear = 302,
    Code = 303,
    Brand = 304,
    Number = 305,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr, Debug)]
#[repr(u16)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum IdentityLinkedIdType {
    Title = 400,
    MiddleName = 401,
    Address1 = 402,
    Address2 = 403,
    Address3 = 404,
    City = 405,
    State = 406,
    PostalCode = 407,
    Country = 408,
    Company = 409,
    Email = 410,
    Phone = 411,
    Ssn = 412,
    Username = 413,
    PassportNumber = 414,
    LicenseNumber = 415,
    FirstName = 416,
    LastName = 417,
    FullName = 418,
}

impl TryFrom<u32> for LinkedIdType {
    type Error = MissingFieldError;

    fn try_from(val: u32) -> Result<Self, Self::Error> {
        let val = serde_json::Value::Number(val.into());
        serde_json::from_value(val).map_err(|_| MissingFieldError("LinkedIdType"))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_linked_id_serialization() {
        use super::{LinkedIdType, LoginLinkedIdType};

        #[derive(serde::Serialize, serde::Deserialize)]
        struct Test {
            id: LinkedIdType,
        }

        let json = "{\"id\":100}";
        let val = serde_json::from_str::<Test>(json).unwrap();

        assert_eq!(val.id, LinkedIdType::Login(LoginLinkedIdType::Username));

        let serialized = serde_json::to_string(&val).unwrap();
        assert_eq!(serialized, json);
    }

    #[cfg(feature = "uniffi")]
    #[test]
    fn test_linked_id_serialization_uniffi() {
        use super::{CardLinkedIdType, LinkedIdType, LoginLinkedIdType};

        assert_eq!(
            100,
            u32::from(LinkedIdType::Login(LoginLinkedIdType::Username))
        );
        assert_eq!(303, u32::from(LinkedIdType::Card(CardLinkedIdType::Code)));

        assert_eq!(
            LinkedIdType::Login(LoginLinkedIdType::Username),
            100.try_into().unwrap()
        );
        assert_eq!(
            LinkedIdType::Card(CardLinkedIdType::Code),
            303.try_into().unwrap()
        );
    }
}
