use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// IPC destination/source endpoint for SDK clients.
pub enum Endpoint {
    /// A web endpoint identified by a runtime-specific numeric id.
    Web {
        /// Runtime-specific identifier for a web endpoint instance.
        id: i32,
    },
    /// Browser foreground endpoint (active web context).
    BrowserForeground,
    /// Browser background endpoint (service worker/background context).
    BrowserBackground,
    /// Desktop renderer endpoint.
    DesktopRenderer,
    /// Desktop main-process endpoint.
    DesktopMain,
}
