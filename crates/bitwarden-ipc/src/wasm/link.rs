use wasm_bindgen::prelude::*;

use crate::destination::Destination;
use crate::link::Link;

#[wasm_bindgen(typescript_custom_section)]
const ITEXT_STYLE: &'static str = r#"
export interface Link {
    send(data: Uint8Array): void;
    receive(): Uint8Array;
    availableDestinations(): Destination[];
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = Link, typescript_type = "Link")]
    pub type JsLink;

    #[wasm_bindgen(method, structural)]
    pub fn send(this: &JsLink, data: &[u8]);

    #[wasm_bindgen(method, structural)]
    pub fn receive(this: &JsLink) -> Vec<u8>;

    #[wasm_bindgen(method, structural)]
    pub fn availableDestinations(this: &JsLink) -> Vec<Destination>;
}

impl Link for JsLink {
    fn send(&self, data: &[u8]) {
        self.send(data);
    }

    fn receive(&self) -> Vec<u8> {
        self.receive()
    }

    fn available_destinations(&self) -> Vec<Destination> {
        self.availableDestinations()
    }
}
