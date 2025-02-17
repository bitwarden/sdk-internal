use crate::endpoint::Endpoint;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify_next::Tsify, wasm_bindgen::prelude::*};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Message {
    pub data: Vec<u8>,
    pub destination: Endpoint,
    // TODO: Consider splitting "Message" into "Outgoing" and "Incoming" types
    // where only "Incoming" has a "source" field
    pub source: Option<Endpoint>,
}
