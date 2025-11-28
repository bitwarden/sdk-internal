use tracing;
use wasm_bindgen::prelude::*;

use crate::{dynamic_tracing::span_factory::SpanFactory, wasm::level::TracingLevel};

#[wasm_bindgen]
pub struct SpanDefinition {
    factory: SpanFactory<'static>,
}

#[wasm_bindgen]
impl SpanDefinition {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, target: String, level: TracingLevel, fields: Vec<String>) -> Self {
        let fields_slice: &[&str] = &fields.iter().map(String::as_str).collect::<Vec<&str>>();
        Self {
            factory: SpanFactory::new(&name, &target, level.into(), None, None, None, fields_slice),
        }
    }

    // TODO: Add fields
    pub fn enter(&self) -> Span {
        let span = self.factory.create().build();
        Span::new(span)
    }
}

#[wasm_bindgen]
pub struct Span {
    _span: tracing::span::EnteredSpan,
}

impl Span {
    fn new(span: tracing::Span) -> Self {
        Self {
            _span: span.entered(),
        }
    }
}
