use tracing::{self};
use wasm_bindgen::prelude::*;

use crate::{
    dynamic_tracing::span_factory::SpanFactory,
    wasm::{EventDefinition, FieldValue, level::TracingLevel},
};

#[wasm_bindgen]
pub struct SpanDefinition {
    factory: SpanFactory<'static>,
}

#[wasm_bindgen]
impl SpanDefinition {
    #[wasm_bindgen(constructor)]
    pub fn new(
        name: String,
        target: String,
        level: TracingLevel,
        fields: Vec<String>,
        file: Option<String>,
        line: Option<u32>,
        module_path: Option<String>,
    ) -> Self {
        let fields_slice: &[&str] = &fields.iter().map(String::as_str).collect::<Vec<&str>>();
        Self {
            factory: SpanFactory::new(
                &name,
                &target,
                level.into(),
                file.as_ref().map(|x| x.as_str()),
                line,
                module_path.as_ref().map(|x| x.as_str()),
                fields_slice,
            ),
        }
    }
    pub fn enter(&self, fields: Vec<FieldValue>) -> Span {
        let span = self.factory.create().build();
        for field in fields {
            span.record(field.name.as_str(), &field.value);
        }
        Span::new(span)
    }

    pub fn enter_with_parent(&self, parent: &Span, fields: Vec<FieldValue>) -> Span {
        let span = self.factory.create().with_parent(parent.span.id()).build();
        // TODO: fix duplicate code
        for field in fields {
            span.record(field.name.as_str(), &field.value);
        }
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
    /// Record a field on the span. Use when the span is already entered
    /// and the field value was not known at span creation time.
    pub fn record(&self, field: FieldValue) {
        self.span.record(field.name.as_str(), &field.value);
    }

    /// Emit an event associated with this span.
    pub fn event(&self, event: &EventDefinition, message: Option<String>) {
        event.record(
            self.span.id(),
            message.unwrap_or_else(|| {
                self.span
                    .metadata()
                    .map(|m| m.name().to_owned())
                    .unwrap_or_default()
            }),
        );
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
