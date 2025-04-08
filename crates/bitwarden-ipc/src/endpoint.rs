use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify_next::Tsify, wasm_bindgen::prelude::*};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum Endpoint {
    Web { id: i32 },
    BrowserForeground,
    BrowserBackground,
    DesktopRenderer,
    DesktopMain,
}
