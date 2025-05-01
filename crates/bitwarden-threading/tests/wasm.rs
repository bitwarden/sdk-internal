// use wasm_bindgen::prelude::*;

// use crate::utils::UnSend;

// #[wasm_bindgen]
// extern "C" {
//     pub type WasmObject;

//     #[wasm_bindgen(constructor)]
//     pub fn new() -> WasmObject;

//     #[wasm_bindgen(method)]
//     pub fn do_something(this: &WasmObject);
// }

// #[wasm_bindgen]
// #[derive(Default)]
// struct WasmObjectWrapper {
//     _marker: std::marker::PhantomData<UnSend>,
// }

// #[wasm_bindgen]
// impl WasmObjectWrapper {
//     pub fn do_something(&self) {}
// }

// #[tokio::test]
// pub async fn test_wasm() {
//     let obj = WasmObject::new();
//     assert!(obj.is_instance_of::<WasmObject>());
// }

// #[tokio::test]
// pub async fn test_move_into_thread() {
//     let obj = WasmObject::new();
//     let value = WasmObjectWrapper::default();

//     tokio::spawn(async move {
//         value.do_something();
//         // This should be a no-op, but it will panic if the object is not Send
//         // let _ = value;

//         // obj.do_something();
//     });
// }
