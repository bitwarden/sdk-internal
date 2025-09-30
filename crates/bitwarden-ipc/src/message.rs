use serde::{Deserialize, Serialize, de::DeserializeOwned};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{endpoint::Endpoint, serde_utils};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct OutgoingMessage {
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter_with_clone))]
    pub payload: Vec<u8>,
    pub destination: Endpoint,
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter_with_clone))]
    pub topic: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct IncomingMessage {
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter_with_clone))]
    pub payload: Vec<u8>,
    pub destination: Endpoint,
    pub source: Endpoint,
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter_with_clone))]
    pub topic: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct TypedOutgoingMessage<Payload> {
    pub payload: Payload,
    pub destination: Endpoint,
}

impl<Payload> TryFrom<OutgoingMessage> for TypedOutgoingMessage<Payload>
where
    Payload: DeserializeOwned,
{
    type Error = serde_utils::SerializeError;

    fn try_from(value: OutgoingMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: serde_utils::from_slice(&value.payload)?,
            destination: value.destination,
        })
    }
}

impl<Payload> TryFrom<TypedOutgoingMessage<Payload>> for OutgoingMessage
where
    Payload: Serialize + PayloadTypeName,
{
    type Error = serde_utils::DeserializeError;

    fn try_from(value: TypedOutgoingMessage<Payload>) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: serde_utils::to_vec(&value.payload)?,
            destination: value.destination,
            topic: Some(Payload::PAYLOAD_TYPE_NAME.to_owned()),
        })
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct TypedIncomingMessage<Payload: PayloadTypeName> {
    pub payload: Payload,
    pub destination: Endpoint,
    pub source: Endpoint,
}

/// This trait is used to ensure that the payload type has a topic associated with it.
pub trait PayloadTypeName {
    const PAYLOAD_TYPE_NAME: &str;
}

impl<Payload> TryFrom<IncomingMessage> for TypedIncomingMessage<Payload>
where
    Payload: DeserializeOwned + PayloadTypeName,
{
    type Error = serde_utils::DeserializeError;

    fn try_from(value: IncomingMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: serde_utils::from_slice(&value.payload)?,
            destination: value.destination,
            source: value.source,
        })
    }
}

impl<Payload> TryFrom<TypedIncomingMessage<Payload>> for IncomingMessage
where
    Payload: Serialize + PayloadTypeName,
{
    type Error = serde_utils::SerializeError;

    fn try_from(value: TypedIncomingMessage<Payload>) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: serde_utils::to_vec(&value.payload)?,
            destination: value.destination,
            source: value.source,
            topic: Some(Payload::PAYLOAD_TYPE_NAME.to_owned()),
        })
    }
}
