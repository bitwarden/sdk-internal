use tracing::{self};
use wasm_bindgen::prelude::*;

use crate::{
    dynamic_tracing::span_factory::SpanFactory,
    wasm::{EventDefinition, level::TracingLevel},
};

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
    span: tracing::span::EnteredSpan,
}

impl Span {
    fn new(span: tracing::Span) -> Self {
        Self {
            span: span.entered(),
        }
    }
}

#[wasm_bindgen]
impl Span {
    pub fn record(&self, event: &EventDefinition, message: String) {
        event.record(self.span.id(), message);
    }

    // Does not work yet due to wasm-bindgen-futures issues
    // #[wasm_bindgen]
    // pub async fn record_async(
    //     &self,
    //     // #[wasm_bindgen(unchecked_param_type = "Promise<EventDefinition>")]
    //     event_promise: Promise,
    // ) -> Result<(), JsValue> {
    //     let event = JsFuture::from(event_promise).await?;
    //     let event = EventDefinition::try_from_js_value_ref(&event)
    //         .ok_or_else(|| Error::new("Expected EventDefinition"))?;
    //     event.record(self.span.id());
    //     Ok(())
    // }
}
