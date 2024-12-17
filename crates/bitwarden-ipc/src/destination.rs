#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum Destination {
    Web,
    BrowserForeground,
    BrowserBackground,
    DesktopRenderer,
    DesktopMain,
}
