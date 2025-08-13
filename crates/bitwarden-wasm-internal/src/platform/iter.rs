use std::str;

use bitwarden_core::Client;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct IteratorClient(Client);

impl IteratorClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl IteratorClient {
    pub fn state(&self) -> IteratorClient {
        IteratorClient::new(self.0.clone())
    }

    pub fn create_js_iterator(&self) -> JsRustIterator {
        to_js_iterator(get_test_iteration())
    }
}

fn get_test_iteration() -> impl Iterator<Item = i32> {
    (0..10).map(|x| x * 2)
}

#[wasm_bindgen]
pub struct JsRustAsyncIterator {
    iter: Box<futures::stream::Stream<Item = i32>>,
}

#[wasm_bindgen]
/// An iterable that wraps a Rust iterator and can be used in JavaScript
pub struct JsRustIterator {
    iter: Box<dyn Iterator<Item = i32>>,
    // next_value: Option<i32>,
}

impl JsRustIterator {
    pub fn new(iter: Box<dyn Iterator<Item = i32>>) -> Self {
        Self { iter }
    }
}

#[wasm_bindgen]
impl JsRustIterator {
    pub fn next(&mut self) -> Option<i32> {
        self.iter.next()
    }
}

// extern "C" {
//     #[wasm_bindgen(js_name = "getTestIteration")]
//     fn get_test_iteration_js() -> js_sys::Iterator;
// }

pub fn to_js_iterator(iter: impl Iterator<Item = i32> + 'static) -> JsRustIterator {
    JsRustIterator::new(Box::new(iter))
}

// #[wasm_bindgen]
// pub struct PlatformClient(Client);
