use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify_next::Tsify, wasm_bindgen::prelude::*};

use crate::endpoint::Endpoint;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct OutgoingMessage {
    pub payload: Vec<u8>,
    pub destination: Endpoint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct IncomingMessage {
    pub payload: Vec<u8>,
    pub destination: Endpoint,
    pub source: Endpoint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    Payload: TryInto<Vec<u8>>,
{
    type Error = <Payload as TryInto<Vec<u8>>>::Error;

    fn try_from(value: TypedOutgoingMessage<Payload>) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: value.payload.try_into()?,
            destination: value.destination,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct TypedIncomingMessage<Payload> {
    pub payload: Payload,
    pub destination: Endpoint,
    pub source: Endpoint,
}

impl<Payload> TryFrom<IncomingMessage> for TypedIncomingMessage<Payload>
where
    Payload: TryFrom<Vec<u8>>,
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
    Payload: TryInto<Vec<u8>>,
{
    type Error = <Payload as TryInto<Vec<u8>>>::Error;

    fn try_from(value: TypedIncomingMessage<Payload>) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: value.payload.try_into()?,
            destination: value.destination,
            source: value.source,
        })
    }
}
