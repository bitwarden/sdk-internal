//! WASM transport for the read-only object-graph introspection surface.
//!
//! Bridges the `bitwarden-introspect` discovery API to JavaScript so automated
//! debugging tooling can crawl live SDK state that a WASM debugger can't reach.
//! Navigation is path-addressed: JS passes a `string[]` path and gets back a
//! JSON snapshot of the addressed node (its preview plus its immediate
//! children), never a live reference into WASM memory.
//!
//! The snapshot is returned as a JSON string that the caller parses. A typed
//! (`tsify`) surface is a later polish; a string keeps the core free of a
//! wasm-bindgen dependency and the transport trivial to reason about.
//!
//! The root is the top-level client, whose `Introspect` impl is generated from
//! its accessor tree (see `introspect_methods` in `bitwarden-pm`). Feature
//! clients appear as children as they gain their own `Introspect` impls.

use bitwarden_introspect::Introspect;
use wasm_bindgen::prelude::*;

/// JS-facing handle for crawling one live SDK object graph.
///
/// Holds an owned, `'static` root. Each `describe` call re-resolves the path
/// from that root and returns an owned snapshot, so nothing borrows across the
/// FFI boundary.
#[wasm_bindgen]
pub struct IntrospectClient {
    root: Box<dyn Introspect>,
}

impl IntrospectClient {
    pub(crate) fn new(root: Box<dyn Introspect>) -> Self {
        Self { root }
    }
}

#[wasm_bindgen]
impl IntrospectClient {
    /// Resolve `path` from the root and return the addressed node's snapshot as
    /// a JSON string, or `undefined` if the path does not resolve. An empty
    /// path yields the root node.
    pub fn describe(&self, path: Vec<String>) -> Result<Option<String>, JsError> {
        let segments: Vec<&str> = path.iter().map(String::as_str).collect();
        match self.root.describe(&segments) {
            Some(node) => {
                let json =
                    serde_json::to_string(&node).map_err(|e| JsError::new(&e.to_string()))?;
                Ok(Some(json))
            }
            None => Ok(None),
        }
    }
}
