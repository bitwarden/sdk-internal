use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::destination::Destination;
use crate::link::Link;

// #[wasm_bindgen(typescript_custom_section)]
// const ITEXT_STYLE: &'static str = r#"
// export interface Link {
//     send(data: Uint8Array): Promise<void>;
//     receive(): Promise<Uint8Array>;
//     availableDestinations(): Destination[];
// }
// "#;

// #[wasm_bindgen]
// extern "C" {
//     #[wasm_bindgen(js_name = Link, typescript_type = "Link")]
//     pub type JsLink;

//     #[wasm_bindgen(method, structural)]
//     pub async fn send(this: &JsLink, data: &[u8]);

//     #[wasm_bindgen(method, structural)]
//     pub async fn receive(this: &JsLink) -> JsValue;

//     #[wasm_bindgen(method, structural)]
//     pub fn availableDestinations(this: &JsLink) -> Vec<Destination>;
// }

// impl Link for JsLink {
//     async fn send(&self, data: &[u8]) {
//         self.send(data).await;
//     }

//     async fn receive(&self) -> Vec<u8> {
//         let js_value = self.receive().await;
//         let array = Uint8Array::new(&js_value);
//         array.to_vec()
//     }

//     fn available_destinations(&self) -> Vec<Destination> {
//         self.availableDestinations()
//     }
// }
