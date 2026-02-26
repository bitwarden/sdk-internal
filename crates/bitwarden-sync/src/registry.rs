//! Generic handler registry providing thread-safe handler storage.
//!
//! This module provides [`HandlerRegistry`], a reusable building block for
//! storing and iterating over trait object handlers behind `Arc`.
//!
//! # Architecture
//!
//! The registry uses interior mutability via `RwLock` to allow
//! handler registration without requiring mutable access. This enables
//! sharing the registry across async boundaries and multiple components.
//!
//! # Execution Model
//!
//! Handlers are stored in registration order. The registry itself does not
//! define execution semantics — callers iterate over handlers and decide
//! how to dispatch them (fail-fast, best-effort, etc.).

use std::sync::{Arc, RwLock};

/// A thread-safe, ordered collection of handlers.
///
/// Supports registration via interior mutability and snapshot-based iteration.
/// The type parameter `H` is typically a `dyn Trait` for trait object storage.
///
/// # Example
///
/// ```ignore
/// let registry = HandlerRegistry::<dyn MyHandler>::new();
/// registry.register(Arc::new(MyHandlerImpl));
///
/// for handler in &registry.handlers() {
///     handler.handle();
/// }
/// ```
pub(crate) struct HandlerRegistry<H: ?Sized> {
    handlers: RwLock<Vec<Arc<H>>>,
}

impl<H: ?Sized> HandlerRegistry<H> {
    /// Create a new empty handler registry.
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(Vec::new()),
        }
    }

    /// Register a new handler.
    ///
    /// Handlers are stored in registration order.
    pub fn register(&self, handler: Arc<H>) {
        self.handlers
            .write()
            .expect("Handler registry lock poisoned")
            .push(handler);
    }

    /// Get a snapshot of all registered handlers.
    ///
    /// Returns a cloned `Vec` so that iteration does not hold the lock.
    pub fn handlers(&self) -> Vec<Arc<H>> {
        self.handlers
            .read()
            .expect("Handler registry lock poisoned")
            .clone()
    }
}

impl<H: ?Sized> Default for HandlerRegistry<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    trait TestTrait: Send + Sync {
        fn name(&self) -> &str;
    }

    struct Named(String);

    impl TestTrait for Named {
        fn name(&self) -> &str {
            &self.0
        }
    }

    #[test]
    fn test_register_and_retrieve_handlers() {
        let registry = HandlerRegistry::<dyn TestTrait>::new();
        registry.register(Arc::new(Named("a".into())));
        registry.register(Arc::new(Named("b".into())));

        let handlers = registry.handlers();
        assert_eq!(handlers.len(), 2);
        assert_eq!(handlers[0].name(), "a");
        assert_eq!(handlers[1].name(), "b");
    }

    #[test]
    fn test_empty_registry_returns_empty_vec() {
        let registry = HandlerRegistry::<dyn TestTrait>::new();
        assert!(registry.handlers().is_empty());
    }

    #[test]
    fn test_default_creates_empty_registry() {
        let registry = HandlerRegistry::<dyn TestTrait>::default();
        assert!(registry.handlers().is_empty());
    }
}
