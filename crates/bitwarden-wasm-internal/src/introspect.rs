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
use bitwarden_introspect::{ChildRef, Introspect, NodeInfo, Writeability};
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
    ///
    /// The hand-rolled async capabilities (see [`CAPABILITIES`]) are overlaid on
    /// the structural graph so a crawler discovers them the same way it finds
    /// derived nodes: their namespace segments appear as children of the nodes
    /// they hang under, and the capability leaves resolve to their own node.
    pub fn describe(&self, path: Vec<String>) -> Result<Option<String>, JsError> {
        let segments: Vec<&str> = path.iter().map(String::as_str).collect();
        let node = match self.root.describe(&segments) {
            // Structural node: fold in any capability children that hang under it
            // (for example `auth` under the root), skipping keys it already has.
            Some(mut node) => {
                for child in capability_children(&segments) {
                    if !node
                        .children
                        .iter()
                        .any(|existing| existing.key == child.key)
                    {
                        node.children.push(child);
                    }
                }
                Some(node)
            }
            // No structural node: the path may still be a capability namespace or
            // a capability leaf that lives outside any derived type.
            None => capability_overlay(&segments),
        };
        match node {
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

/// A hand-rolled capability's metadata: where it sits in the crawlable path
/// space and how it presents there. The [`describe`](IntrospectClient::describe)
/// overlay is generated from this list, so a capability appears in the graph
/// with no bespoke describe code.
///
/// This is the metadata half of the registry; the typed read/write logic lives
/// in [`IntrospectClient::read_capability`] / [`write_capability`]. Every entry
/// here must have a matching arm in both, and every arm an entry here, so the
/// graph advertises exactly what the verbs accept.
struct Capability {
    /// Full path to the capability leaf, e.g. `["auth", "login_method"]`.
    path: &'static [&'static str],
    /// Static type name reported for the leaf node.
    type_name: &'static str,
    /// How the leaf is written.
    writeability: Writeability,
}

const CAPABILITIES: &[Capability] = &[Capability {
    path: &["auth", "login_method"],
    type_name: "UserLoginMethod",
    writeability: Writeability::Capability,
}];

/// Type name for a synthetic namespace node — an interior path segment (such as
/// `auth`) that exists only to group capabilities and has no backing value.
const CAPABILITY_NAMESPACE_TYPE: &str = "IntrospectCapabilities";

/// Preview string shared by every synthetic namespace node.
const NAMESPACE_PREVIEW: &str = "{ hand-rolled capabilities }";

/// The [`NodeInfo`] for a capability path, or `None` when `path` is neither a
/// capability leaf nor a namespace grouping one. Consulted only when the
/// structural graph does not itself resolve `path`.
fn capability_overlay(path: &[&str]) -> Option<NodeInfo> {
    if let Some(capability) = CAPABILITIES
        .iter()
        .find(|capability| capability.path == path)
    {
        return Some(capability_leaf_node(capability));
    }
    let children = capability_children(path);
    if children.is_empty() {
        None
    } else {
        Some(namespace_node(children))
    }
}

/// The immediate capability children hanging directly under `prefix` (the root
/// `[]` or an interior namespace). A child is a leaf when its path ends one
/// segment past `prefix`, otherwise a nested namespace.
fn capability_children(prefix: &[&str]) -> Vec<ChildRef> {
    let mut children: Vec<ChildRef> = Vec::new();
    for capability in CAPABILITIES {
        let under_prefix = capability.path.len() > prefix.len()
            && capability
                .path
                .iter()
                .zip(prefix)
                .all(|(seg, want)| seg == want);
        if !under_prefix {
            continue;
        }
        let key = capability.path[prefix.len()];
        if children.iter().any(|child| child.key == key) {
            continue;
        }
        let node = if capability.path.len() == prefix.len() + 1 {
            capability_leaf_node(capability)
        } else {
            namespace_node(Vec::new())
        };
        children.push(ChildRef {
            key: key.to_string(),
            type_name: node.type_name,
            preview: node.preview,
            writeability: node.writeability,
        });
    }
    children
}

fn capability_leaf_node(capability: &Capability) -> NodeInfo {
    NodeInfo {
        type_name: capability.type_name,
        preview: format!("{} (hand-rolled capability)", capability.type_name),
        writeability: capability.writeability,
        children: Vec::new(),
    }
}

fn namespace_node(children: Vec<ChildRef>) -> NodeInfo {
    NodeInfo {
        type_name: CAPABILITY_NAMESPACE_TYPE,
        preview: NAMESPACE_PREVIEW.to_string(),
        writeability: Writeability::ReadOnly,
        children,
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

// Async capability registry: the typed read/write logic for hand-rolled
// capabilities that reach past the public API, each addressed by path. Adding a
// capability is an arm here, a matching [`CAPABILITIES`] entry so `describe`
// surfaces it, and a core `debug_*` function — the JS surface stays a fixed set
// of generic verbs.
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
