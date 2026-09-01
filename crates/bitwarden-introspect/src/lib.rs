//! Compile-time-gated runtime introspection of the SDK object graph.
//!
//! This crate lets automated debugging tooling crawl the live SDK state that a
//! WASM/native debugger can't easily reach. Types opt in with
//! `#[derive(Introspect)]`; the discovery API then walks them one path segment
//! at a time, returning owned snapshots ([`NodeInfo`]) rather than references,
//! so lock-guarded nodes can be read without handing out a borrow that would
//! outlive its guard.
//!
//! Writing is expressed through the per-node [`Writeability`] descriptor and
//! the [`Debuggable`] wrapper. `Debuggable<T>` is `#[repr(transparent)]` over
//! `T` unless the `introspect` feature is on, so it costs nothing in builds
//! that don't enable introspection.
//!
//! This is an early sketch: the read/discovery path and the `Debuggable`
//! mechanism are implemented; path-addressed writing and serialization of
//! snapshots are left as follow-ups (see the design doc under `docs/plans`).

// Allow this crate to refer to itself by name so the derive macro's
// `::bitwarden_introspect::…` paths resolve in the crate's own tests.
extern crate self as bitwarden_introspect;

pub use bitwarden_introspect_macro::Introspect;

/// Whether, and by what mechanism, a node can be mutated. Surfaced in the
/// discovery API so a caller knows what a node supports before attempting a
/// write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writeability {
    /// Cannot be written through the introspection surface.
    ReadOnly,
    /// Written by cloning the nearest lock-guarded ancestor, applying the
    /// change, and storing it back. Requires the ancestor and the intervening
    /// values to be `Clone`.
    CloneReplace,
    /// Written in place through a shared reference, backed by [`Debuggable`],
    /// so the change is visible to every holder of the same value.
    InPlace,
}

/// A single edge from a node to one of its immediate children.
#[derive(Debug, Clone)]
pub struct ChildRef {
    /// Field name, collection index, or variant name used to descend.
    pub key: String,
    /// Static type name of the child value.
    pub type_name: &'static str,
    /// Short, human-readable rendering of the child's own value.
    pub preview: String,
    /// Whether the child can be written.
    pub writeability: Writeability,
}

/// A snapshot of one node in the object graph: its own value preview plus the
/// edges to its immediate children.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// Static type name of this node.
    pub type_name: &'static str,
    /// Short, human-readable rendering of this node's own value.
    pub preview: String,
    /// Whether this node can be written.
    pub writeability: Writeability,
    /// Edges to this node's immediate children.
    pub children: Vec<ChildRef>,
}

/// Opt-in introspection over a value and the graph reachable from it.
///
/// Derive it with `#[derive(Introspect)]`. Navigation is path-addressed and
/// returns owned snapshots so lock-guarded nodes are safe to read.
pub trait Introspect {
    /// This node's own snapshot: preview plus its immediate children.
    fn node_info(&self) -> NodeInfo;

    /// Resolve `path` starting at this node. An empty path yields this node's
    /// own [`NodeInfo`]; otherwise the head segment selects a child and the
    /// tail is resolved against it. Returns `None` if any segment fails to
    /// resolve.
    fn describe(&self, path: &[&str]) -> Option<NodeInfo>;
}

macro_rules! leaf_introspect {
    ($($t:ty),* $(,)?) => {$(
        impl Introspect for $t {
            fn node_info(&self) -> NodeInfo {
                NodeInfo {
                    type_name: stringify!($t),
                    preview: format!("{:?}", self),
                    writeability: Writeability::ReadOnly,
                    children: Vec::new(),
                }
            }

            fn describe(&self, path: &[&str]) -> Option<NodeInfo> {
                if path.is_empty() {
                    Some(self.node_info())
                } else {
                    None
                }
            }
        }
    )*};
}

leaf_introspect!(
    bool, char, String, i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize, f32, f64
);

impl<T: Introspect> Introspect for Vec<T> {
    fn node_info(&self) -> NodeInfo {
        let children = self
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let node = value.node_info();
                ChildRef {
                    key: index.to_string(),
                    type_name: node.type_name,
                    preview: node.preview,
                    writeability: node.writeability,
                }
            })
            .collect();
        NodeInfo {
            type_name: "Vec",
            preview: format!("[{} items]", self.len()),
            writeability: Writeability::ReadOnly,
            children,
        }
    }

    fn describe(&self, path: &[&str]) -> Option<NodeInfo> {
        match path.split_first() {
            None => Some(self.node_info()),
            Some((head, rest)) => head
                .parse::<usize>()
                .ok()
                .and_then(|index| self.get(index))
                .and_then(|value| value.describe(rest)),
        }
    }
}

impl<T: Introspect> Introspect for Option<T> {
    fn node_info(&self) -> NodeInfo {
        let children = match self {
            Some(value) => {
                let node = value.node_info();
                vec![ChildRef {
                    key: "Some".to_string(),
                    type_name: node.type_name,
                    preview: node.preview,
                    writeability: node.writeability,
                }]
            }
            None => Vec::new(),
        };
        NodeInfo {
            type_name: "Option",
            preview: if self.is_some() { "Some(..)" } else { "None" }.to_string(),
            writeability: Writeability::ReadOnly,
            children,
        }
    }

    fn describe(&self, path: &[&str]) -> Option<NodeInfo> {
        match path.split_first() {
            None => Some(self.node_info()),
            Some((head, rest)) if *head == "Some" => {
                self.as_ref().and_then(|value| value.describe(rest))
            }
            Some(_) => None,
        }
    }
}

#[cfg(not(feature = "introspect"))]
mod debuggable_impl {
    /// A field a developer has marked as worth inspecting at runtime.
    ///
    /// Without the `introspect` feature this is a zero-cost, transparent
    /// wrapper over `T`: it derefs to `T`, so read sites see the plain value.
    #[repr(transparent)]
    pub struct Debuggable<T>(pub(crate) T);

    impl<T> Debuggable<T> {
        /// Borrow the wrapped value.
        pub fn get(&self) -> &T {
            &self.0
        }

        /// Replace the wrapped value. Requires exclusive access in this build.
        pub fn set(&mut self, value: T) {
            self.0 = value;
        }
    }

    impl<T> core::ops::Deref for Debuggable<T> {
        type Target = T;
        fn deref(&self) -> &T {
            &self.0
        }
    }

    impl<T> core::ops::DerefMut for Debuggable<T> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0
        }
    }

    impl<T> From<T> for Debuggable<T> {
        fn from(value: T) -> Self {
            Debuggable(value)
        }
    }
}

#[cfg(feature = "introspect")]
mod debuggable_impl {
    use std::sync::{RwLock, RwLockReadGuard};

    /// A field a developer has marked as worth inspecting at runtime.
    ///
    /// With the `introspect` feature the value is lock-guarded, so it can be
    /// written in place through a shared reference. This deliberately differs
    /// in layout from the release-shaped build; only ever enable the feature
    /// in dev builds.
    pub struct Debuggable<T>(pub(crate) RwLock<T>);

    impl<T> Debuggable<T> {
        /// Acquire a read guard over the wrapped value.
        pub fn get(&self) -> RwLockReadGuard<'_, T> {
            self.0.read().expect("Debuggable lock poisoned")
        }

        /// Replace the wrapped value in place through a shared reference.
        pub fn set(&self, value: T) {
            *self.0.write().expect("Debuggable lock poisoned") = value;
        }
    }

    impl<T> From<T> for Debuggable<T> {
        fn from(value: T) -> Self {
            Debuggable(RwLock::new(value))
        }
    }
}

pub use debuggable_impl::Debuggable;

// One impl serves both builds: `get()` yields either `&T` or a read guard,
// both of which deref to `T`, and the node is always reported as writable in
// place because that is what `Debuggable` grants under the feature.
impl<T: Introspect> Introspect for Debuggable<T> {
    fn node_info(&self) -> NodeInfo {
        let inner = self.get();
        let mut node = (*inner).node_info();
        node.writeability = Writeability::InPlace;
        node
    }

    fn describe(&self, path: &[&str]) -> Option<NodeInfo> {
        let inner = self.get();
        (*inner).describe(path).map(|mut node| {
            if path.is_empty() {
                node.writeability = Writeability::InPlace;
            }
            node
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[derive(Introspect)]
    struct Cipher {
        title: String,
        #[introspect(skip)]
        _cache_generation: u32,
    }

    #[derive(Introspect)]
    struct Vault {
        name: String,
        ciphers: Vec<Cipher>,
        #[introspect(writable)]
        note: String,
        secret: Debuggable<String>,
    }

    fn sample() -> Vault {
        Vault {
            name: "personal".to_string(),
            ciphers: vec![
                Cipher {
                    title: "email".to_string(),
                    _cache_generation: 1,
                },
                Cipher {
                    title: "bank".to_string(),
                    _cache_generation: 2,
                },
            ],
            note: "todo".to_string(),
            secret: Debuggable::from("s3cr3t".to_string()),
        }
    }

    #[test]
    fn root_lists_fields_in_order() {
        let root = sample().describe(&[]).unwrap();
        let keys: Vec<&str> = root.children.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["name", "ciphers", "note", "secret"]);
    }

    #[test]
    fn skip_attribute_hides_field() {
        let node = Cipher {
            title: "x".to_string(),
            _cache_generation: 9,
        }
        .node_info();
        let keys: Vec<&str> = node.children.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["title"]);
    }

    #[test]
    fn descends_through_collections() {
        let node = sample().describe(&["ciphers", "1", "title"]).unwrap();
        assert_eq!(node.type_name, "String");
        assert_eq!(node.preview, "\"bank\"");
    }

    #[test]
    fn writable_attribute_reports_clone_replace() {
        let root = sample().describe(&[]).unwrap();
        let note = root.children.iter().find(|c| c.key == "note").unwrap();
        assert_eq!(note.writeability, Writeability::CloneReplace);
    }

    #[test]
    fn debuggable_reports_in_place() {
        let root = sample().describe(&[]).unwrap();
        let secret = root.children.iter().find(|c| c.key == "secret").unwrap();
        assert_eq!(secret.writeability, Writeability::InPlace);
    }
}
