//! WASM transport for the object-graph introspection surface.
//!
//! Bridges the `bitwarden-introspect` discovery API to JavaScript so automated
//! debugging tooling can crawl live SDK state that a WASM debugger can't reach.
//! Everything is path-addressed, and the JS surface is a small, fixed set of
//! generic verbs rather than one method per capability:
//!
//! - `describe(path)` — synchronous structural crawl: the node's type, value preview, writeability,
//!   and immediate children. Never awaits.
//! - `read(path)` — asynchronous value read. Resolves hand-rolled capabilities whose state lives
//!   behind async APIs (e.g. the login method); for ordinary sync nodes it returns the value
//!   preview.
//! - `write(path, value)` — asynchronous value write.
//!
//! Adding a capability means registering a node (a match arm below plus a core
//! `debug_*` function), not adding a public method, so this class does not grow
//! as capabilities are added. Snapshots cross as JSON strings the caller parses;
//! a typed (`tsify`) surface is a later polish.

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
    /// Structural crawl: the [`NodeInfo`](bitwarden_introspect::NodeInfo) at
    /// `path` as JSON (type, preview, writeability, children), or `undefined` if
    /// the path does not resolve. An empty path yields the root. Synchronous.
    pub fn describe(&self, path: Vec<String>) -> Result<Option<String>, JsError> {
        let segments: Vec<&str> = path.iter().map(String::as_str).collect();
        match self.root.describe(&segments) {
            Some(node) => Ok(Some(to_json(&node)?)),
            None => Ok(None),
        }
    }

    /// Read the value at `path` as JSON, or `undefined` if it does not resolve.
    ///
    /// Asynchronous so it can resolve capabilities whose state lives behind
    /// async APIs; ordinary synchronous nodes resolve to their value preview.
    pub async fn read(&self, path: Vec<String>) -> Result<Option<String>, JsError> {
        let segments: Vec<&str> = path.iter().map(String::as_str).collect();
        match self.read_capability(&segments).await? {
            CapabilityRead::Handled(value) => Ok(value),
            CapabilityRead::NotACapability => {
                Ok(self.root.describe(&segments).map(|node| node.preview))
            }
        }
    }

    /// Write `value` (JSON) to the node at `path`. Asynchronous. Errors if the
    /// path is not a writable capability.
    pub async fn write(&self, path: Vec<String>, value: String) -> Result<(), JsError> {
        let segments: Vec<&str> = path.iter().map(String::as_str).collect();
        if self.write_capability(&segments, &value).await? {
            Ok(())
        } else {
            Err(JsError::new(&format!(
                "`{}` is not a writable capability",
                path.join("/")
            )))
        }
    }
}

/// Outcome of trying to resolve a path as an async capability.
enum CapabilityRead {
    /// The path is a registered capability; the value is its JSON (or `None`).
    Handled(Option<String>),
    /// The path is not an async capability; the caller should fall back to the
    /// synchronous graph.
    NotACapability,
}

// Async capability registry: hand-rolled capabilities that reach past the public
// API, each addressed by path. Extending this is adding an arm here plus a core
// `debug_*` function, keeping the JS surface a fixed set of generic verbs.
impl IntrospectClient {
    async fn read_capability(&self, path: &[&str]) -> Result<CapabilityRead, JsError> {
        match path {
            ["auth", "login_method"] => {
                let method = bitwarden_core::introspect::debug_get_login_method(&self.client).await;
                let value = match method {
                    Some(method) => Some(to_json(&method)?),
                    None => None,
                };
                Ok(CapabilityRead::Handled(value))
            }
            _ => Ok(CapabilityRead::NotACapability),
        }
    }

    async fn write_capability(&self, path: &[&str], value: &str) -> Result<bool, JsError> {
        match path {
            ["auth", "login_method"] => {
                let method: UserLoginMethod = from_json(value)?;
                bitwarden_core::introspect::debug_set_login_method(&self.client, method).await;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(|e| JsError::new(&e.to_string()))
}

fn from_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, JsError> {
    serde_json::from_str(value).map_err(|e| JsError::new(&e.to_string()))
}
