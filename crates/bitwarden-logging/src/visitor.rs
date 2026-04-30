//! Visitor for extracting fields from tracing events.

use std::collections::HashMap;

use tracing::field::{Field, Visit};

/// Extracts the message and structured fields from a tracing event.
#[derive(Debug, Default)]
pub struct MessageVisitor {
    /// The extracted message, if present.
    pub message: String,
    /// Additional structured fields from the event.
    pub fields: HashMap<String, String>,
}

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            self.fields
                .insert(field.name().to_string(), format!("{:?}", value));
        }
    }
}

#[cfg(test)]
mod tests {
    use tracing::Level;

    use super::*;

    #[test]
    fn test_visitor_extracts_message() {
        let fields = tracing::field::FieldSet::new(
            &["message"],
            tracing::callsite::Identifier(&TEST_CALLSITE),
        );

        let mut visitor = MessageVisitor::default();
        assert!(visitor.message.is_empty());
        assert!(visitor.fields.is_empty());

        let field = fields.field("message").expect("field should exist");
        visitor.record_str(&field, "hello world");
        assert_eq!(visitor.message, "hello world");
    }

    #[test]
    fn test_visitor_extracts_extra_fields() {
        let fields = tracing::field::FieldSet::new(
            &["message", "user_id"],
            tracing::callsite::Identifier(&TEST_CALLSITE),
        );

        let mut visitor = MessageVisitor::default();

        let msg_field = fields.field("message").expect("field should exist");
        visitor.record_str(&msg_field, "login attempt");

        let id_field = fields.field("user_id").expect("field should exist");
        visitor.record_str(&id_field, "abc-123");

        assert_eq!(visitor.message, "login attempt");
        assert_eq!(visitor.fields.get("user_id"), Some(&"abc-123".to_string()));
    }

    #[test]
    fn test_visitor_record_debug_fallback() {
        let fields = tracing::field::FieldSet::new(
            &["message", "count"],
            tracing::callsite::Identifier(&TEST_CALLSITE),
        );

        let mut visitor = MessageVisitor::default();

        let count_field = fields.field("count").expect("field should exist");
        visitor.record_debug(&count_field, &42);

        assert_eq!(visitor.fields.get("count"), Some(&"42".to_string()));
    }

    // Minimal callsite for constructing FieldSet in tests
    static TEST_CALLSITE: TestCallsite = TestCallsite;

    struct TestCallsite;

    impl tracing::callsite::Callsite for TestCallsite {
        fn set_interest(&self, _interest: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            static META: std::sync::LazyLock<tracing::Metadata<'static>> =
                std::sync::LazyLock::new(|| {
                    tracing::metadata::Metadata::new(
                        "test",
                        "test_target",
                        Level::INFO,
                        None,
                        None,
                        None,
                        tracing::field::FieldSet::new(
                            &[],
                            tracing::callsite::Identifier(&TEST_CALLSITE),
                        ),
                        tracing::metadata::Kind::EVENT,
                    )
                });
            &META
        }
    }
}
