//! Serde helpers for [`http::StatusCode`], used via `#[serde(with = ...)]`.

use http::StatusCode;
use serde::{Deserialize, Deserializer, Serializer, de::Error};

pub fn serialize<S: Serializer>(status: &StatusCode, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_u16(status.as_u16())
}

pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<StatusCode, D::Error> {
    let value = u16::deserialize(de)?;
    StatusCode::from_u16(value).map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Wrapper {
        #[serde(with = "super")]
        status: StatusCode,
    }

    #[test]
    fn serializes_as_u16() {
        let json = serde_json::to_string(&Wrapper {
            status: StatusCode::NOT_FOUND,
        })
        .unwrap();
        assert_eq!(json, r#"{"status":404}"#);
    }

    #[test]
    fn deserializes_from_u16() {
        let wrapper: Wrapper = serde_json::from_str(r#"{"status":201}"#).unwrap();
        assert_eq!(wrapper.status, StatusCode::CREATED);
    }

    #[test]
    fn rejects_invalid_status() {
        let err = serde_json::from_str::<Wrapper>(r#"{"status":99}"#).unwrap_err();
        assert!(err.to_string().contains("invalid status code"));
    }
}
