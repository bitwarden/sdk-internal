use tracing::span::Id;
use wasm_bindgen::prelude::*;

use crate::{dynamic_tracing::event_factory::EventFactory, wasm::level::TracingLevel};

#[wasm_bindgen]
pub struct EventDefinition {
    factory: EventFactory<'static>,
}

#[wasm_bindgen]
impl EventDefinition {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, target: String, level: TracingLevel, fields: Vec<String>) -> Self {
        let mut fields_slice = fields.iter().map(String::as_str).collect::<Vec<&str>>();
        fields_slice.push("message");
        Self {
            factory: EventFactory::new(
                &name,
                &target,
                level.into(),
                None,
                None,
                None,
                &fields_slice,
            ),
        }
    }
}

impl EventDefinition {
    pub fn record(&self, span_id: Option<Id>, message: String) {
        self.factory
            .create()
            .with_span_id(span_id)
            .with("message", &message)
            .build();
    }
}
