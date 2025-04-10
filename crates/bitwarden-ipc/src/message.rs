use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::endpoint::Endpoint;

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

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct TypedOutgoingMessage<Payload> {
    pub payload: Payload,
    pub destination: Endpoint,
}

impl<Payload> TryFrom<OutgoingMessage> for TypedOutgoingMessage<Payload>
where
    Payload: TryFrom<Vec<u8>>,
{
    type Error = <Payload as TryFrom<Vec<u8>>>::Error;

    fn try_from(value: OutgoingMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: Payload::try_from(value.payload)?,
            destination: value.destination,
        })
    }
}

impl<Payload> TryFrom<TypedOutgoingMessage<Payload>> for OutgoingMessage
where
    Payload: TryInto<Vec<u8>> + PayloadTypeName,
{
    type Error = <Payload as TryInto<Vec<u8>>>::Error;

    fn try_from(value: TypedOutgoingMessage<Payload>) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: value.payload.try_into()?,
            destination: value.destination,
            topic: Some(Payload::name()),
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
    fn name() -> String;
}

impl<Payload> TryFrom<IncomingMessage> for TypedIncomingMessage<Payload>
where
    Payload: TryFrom<Vec<u8>> + PayloadTypeName,
{
    type Error = <Payload as TryFrom<Vec<u8>>>::Error;

    fn try_from(value: IncomingMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: Payload::try_from(value.payload)?,
            destination: value.destination,
            source: value.source,
        })
    }
}

impl<Payload> TryFrom<TypedIncomingMessage<Payload>> for IncomingMessage
where
    Payload: TryInto<Vec<u8>> + PayloadTypeName,
{
    type Error = <Payload as TryInto<Vec<u8>>>::Error;

    fn try_from(value: TypedIncomingMessage<Payload>) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: value.payload.try_into()?,
            destination: value.destination,
            source: value.source,
            topic: Some(Payload::name()),
        })
    }
}
