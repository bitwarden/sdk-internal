use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::destination::Destination;
use crate::link::Link;

#[wasm_bindgen]
pub fn create_link() -> Link {
    let link = Link::new();
    link
}

#[wasm_bindgen]
pub fn send(link: &Link, data: Vec<u8>) {
    link.send(data);
}
