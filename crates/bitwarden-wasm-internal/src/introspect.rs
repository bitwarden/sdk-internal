//! WASM transport for the object-graph introspection surface.
//!
//! Bridges the `bitwarden-introspect` discovery API to JavaScript so automated
//! debugging tooling can crawl live SDK state that a WASM debugger can't reach.
//! Navigation is path-addressed: JS passes a `string[]` path and gets back a
//! JSON snapshot of the addressed node (its preview plus its immediate
//! children), never a live reference into WASM memory.
//!
//! Snapshots are returned as JSON strings that the caller parses. A typed
//! (`tsify`) surface is a later polish; a string keeps the core free of a
//! wasm-bindgen dependency and the transport trivial to reason about.
//!
//! Two lanes:
//! - `describe` is the synchronous crawl over the accessor tree (its root's `Introspect` impl is
//!   generated from `bitwarden-pm`'s accessors).
//! - `read_login_method` / `write_login_method` are the asynchronous lane for hand-rolled
//!   capabilities that reach past the public API. Their state lives behind the async state
//!   registry, so these are `async` (JS Promises); the sync crawl is unaffected.

use bitwarden_core::{Client, client::login_method::UserLoginMethod};
use bitwarden_introspect::Introspect;
use wasm_bindgen::prelude::*;

/// JS-facing handle for crawling one live SDK object graph.
///
/// Holds an owned, `'static` root for the synchronous crawl plus a clone of the
/// [`Client`] (same `Arc`-backed state) for the asynchronous hand-rolled
/// capabilities. Each call re-resolves from these and returns an owned result,
/// so nothing borrows across the FFI boundary.
#[wasm_bindgen]
pub struct IntrospectClient {
    root: Box<dyn Introspect>,
    client: Client,
}

impl IntrospectClient {
    pub(crate) fn new(root: Box<dyn Introspect>, client: Client) -> Self {
        Self { root, client }
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

    /// Read the user's current login method as JSON, or `undefined` if none is
    /// set. This is a hand-rolled capability: the login method is not exposed by
    /// the public API and is read asynchronously from the state registry.
    pub async fn read_login_method(&self) -> Result<Option<String>, JsError> {
        match bitwarden_core::introspect::debug_get_login_method(&self.client).await {
            Some(method) => {
                let json =
                    serde_json::to_string(&method).map_err(|e| JsError::new(&e.to_string()))?;
                Ok(Some(json))
            }
            None => Ok(None),
        }
    }

    /// Overwrite the user's current login method from JSON. Debug-only: bypasses
    /// the normal login flow to drive the client into a specific state.
    pub async fn write_login_method(&self, value: String) -> Result<(), JsError> {
        let method: UserLoginMethod =
            serde_json::from_str(&value).map_err(|e| JsError::new(&e.to_string()))?;
        bitwarden_core::introspect::debug_set_login_method(&self.client, method).await;
        Ok(())
    }
}
