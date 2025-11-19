use tracing_dynamic::EventFactory;
use wasm_bindgen::prelude::*;

use crate::wasm::level::TracingLevel;

#[wasm_bindgen]
pub struct EventDefinition {
    factory: EventFactory<'static>,
}

#[wasm_bindgen]
impl EventDefinition {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, target: String, level: TracingLevel, fields: Vec<String>) -> Self {
        let fields_slice: &[&str] = &fields.iter().map(String::as_str).collect::<Vec<&str>>();
        Self {
            factory: EventFactory::new(
                &name,
                &target,
                level.into(),
                None,
                None,
                None,
                fields_slice,
            ),
        }
    }

    // TODO: Add fields
    pub fn record(&self) {
        self.factory.create().build();
    }
}
