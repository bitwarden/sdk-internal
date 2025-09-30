//! This file contains message serialization for messages intended to be signed.
//!
//! Consumers of the signing API should not care about or implement individual ways to represent
//! structs. Thus, the only publicly exposed api takes a struct, and the signing module takes care
//! of the serialization under the hood. This requires converting the struct to a byte array
//! using some serialization format. Further, the serialization format must be written to the
//! signature object so that it can be used upon deserialization to use the correct deserializer.
//!
//! To provide this interface, the SerializedMessage struct is introduced. SerializedMessage
//! represents the serialized bytes along with the content format used for serialization. The latter
//! is stored on the signed object, in e.g. a COSE header, so that upon deserialization the correct
//! deserializer can be used.
//!
//! Currently, only CBOR serialization / deserialization is implemented, since it is compact and is
//! what COSE already uses.

use coset::iana::CoapContentFormat;
use serde::{Serialize, de::DeserializeOwned};

use crate::error::EncodingError;

/// A message (struct) to be signed, serialized to a byte array, along with the content format of
/// the bytes.
pub struct SerializedMessage {
    serialized_message_bytes: Vec<u8>,
    content_type: CoapContentFormat,
}

impl AsRef<[u8]> for SerializedMessage {
    fn as_ref(&self) -> &[u8] {
        &self.serialized_message_bytes
    }
}

impl SerializedMessage {
    /// Creates a new `SerializedMessage` from a byte array and content type.
    pub fn from_bytes(bytes: Vec<u8>, content_type: CoapContentFormat) -> Self {
        SerializedMessage {
            serialized_message_bytes: bytes,
            content_type,
        }
    }

    /// Returns the serialized message bytes as a slice. This representation needs to be used
    /// together with a content type to deserialize the message correctly.
    pub fn as_bytes(&self) -> &[u8] {
        &self.serialized_message_bytes
    }

    pub(super) fn content_type(&self) -> CoapContentFormat {
        self.content_type
    }

    /// Encodes a message into a `SerializedMessage` using CBOR serialization.
    pub(super) fn encode<Message: Serialize>(message: &Message) -> Result<Self, EncodingError> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(message, &mut buffer)
            .map_err(|_| EncodingError::InvalidCborSerialization)?;
        Ok(SerializedMessage {
            serialized_message_bytes: buffer,
            content_type: CoapContentFormat::Cbor,
        })
    }

    /// Creates a new `SerializedMessage` from a byte array and content type.
    /// This currently implements only CBOR serialization, so the content type must be `Cbor`.
    pub fn decode<Message: DeserializeOwned>(&self) -> Result<Message, EncodingError> {
        if self.content_type != CoapContentFormat::Cbor {
            return Err(EncodingError::InvalidValue("Unsupported content type"));
        }

        ciborium::de::from_reader(self.serialized_message_bytes.as_slice())
            .map_err(|_| EncodingError::InvalidCborSerialization)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestMessage {
        field1: String,
        field2: u32,
    }

    #[test]
    fn test_serialization() {
        let message = TestMessage {
            field1: "Hello".to_string(),
            field2: 42,
        };

        let serialized = SerializedMessage::encode(&message).unwrap();
        let deserialized: TestMessage = serialized.decode().unwrap();

        assert_eq!(message, deserialized);
    }

    #[test]
    fn test_bytes() {
        let message = TestMessage {
            field1: "Hello".to_string(),
            field2: 42,
        };

        let serialized = SerializedMessage::encode(&message).unwrap();
        let deserialized: TestMessage = SerializedMessage::from_bytes(
            serialized.as_bytes().to_vec(),
            serialized.content_type(),
        )
        .decode()
        .unwrap();
        assert_eq!(message, deserialized);
    }
}
