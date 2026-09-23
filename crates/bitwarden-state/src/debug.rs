//! Dev-only generic debug browse over the registry's repositories.
//!
//! [`StateDebug`](crate::debug::StateDebug) is the exposed handle: a typed
//! browse over every registered repository, addressed by string type name and
//! key, for automated tooling that needs to reach state the type-safe public API
//! does not expose generically. It reads through a parallel index of per-type
//! get/set/list shims, captured where each type is still known (client-managed
//! registration and the SDK-managed migration path) and dispatched by the
//! repository's string name. Compiled only under the `debug-capabilities`
//! feature; never ship in production.

use std::{
    any::TypeId,
    collections::HashMap,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::{Arc, RwLock},
};

use serde_json::Value;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    registry::StateRegistry,
    repository::{RepositoryItem, RepositoryMigrations},
};

/// Typed debug handle over the SDK's state registry: a generic browse across
/// every registered repository, both client-managed and SDK-managed.
///
/// Holds a cheap, `Arc`-backed handle to the registry, so nothing borrows across
/// the FFI boundary. Reached through the client's debug tree; bypasses the
/// type-safe public API.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct StateDebug {
    registry: Arc<StateRegistry>,
}

impl StateDebug {
    /// Wrap the owning registry handle. Reached through [`StateRegistryDebugExt`].
    pub(crate) fn new(registry: Arc<StateRegistry>) -> Self {
        Self { registry }
    }
}

/// Yields the debug handle for a state registry.
///
/// Implemented on `Arc<StateRegistry>` (not `StateRegistry`) because the handle
/// owns its registry, so nothing borrows across the FFI boundary. The debug tree
/// gets the shared registry from the client and calls this.
pub trait StateRegistryDebugExt {
    /// Debug browse over this registry.
    fn debug(&self) -> StateDebug;
}

impl StateRegistryDebugExt for Arc<StateRegistry> {
    fn debug(&self) -> StateDebug {
        StateDebug::new(self.clone())
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl StateDebug {
    /// Names of every registered repository (client- and SDK-managed).
    pub fn types(&self) -> Vec<String> {
        self.registry.debug_types()
    }

    /// List a repository's values as a JSON-array string (`JSON.parse` it),
    /// addressed by type name. Values only (no keys). Raw stored JSON.
    pub async fn list(&self, type_name: String) -> String {
        Value::Array(self.registry.debug_list(&type_name).await).to_string()
    }

    /// Read one item by type name and string key, as a JSON string (`"null"` if
    /// absent).
    pub async fn get(&self, type_name: String, key: String) -> String {
        self.registry
            .debug_get(&type_name, &key)
            .await
            .unwrap_or(Value::Null)
            .to_string()
    }

    /// Write one item by type name and string key. `value` is the item as a JSON
    /// string. Returns `true` if the write landed; `false` on a bad JSON string,
    /// an unknown type, a bad key, a value that does not deserialize, or a failed
    /// write, so a caller (e.g. a seeding harness) can tell a no-op from a write.
    pub async fn set(&self, type_name: String, key: String, value: String) -> bool {
        let Ok(value) = serde_json::from_str::<Value>(&value) else {
            return false;
        };
        self.registry.debug_set(&type_name, &key, value).await
    }
}

/// A future borrowing the registry, boxed so it can cross a fn pointer. `Send`
/// so the handle's async methods can run on a multi-threaded runtime (uniffi).
type DebugFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// Shim: list a repository's values as JSON.
type DebugListFn = for<'a> fn(&'a StateRegistry) -> DebugFuture<'a, Vec<Value>>;
/// Shim: read one item by string key as JSON.
type DebugGetFn = for<'a> fn(&'a StateRegistry, &'a str) -> DebugFuture<'a, Option<Value>>;
/// Shim: write one item by string key. Reports whether the write landed.
type DebugSetFn = for<'a> fn(&'a StateRegistry, &'a str, Value) -> DebugFuture<'a, bool>;

/// Monomorphized get/set/list shims for one repository type, so the registry can
/// offer generic string-addressed access without naming the type. Captured at
/// the point where the concrete type is still known.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DebugRepo {
    name: &'static str,
    list: DebugListFn,
    get: DebugGetFn,
    set: DebugSetFn,
}

impl DebugRepo {
    /// Capture the shims for a concrete repository type.
    pub(crate) fn for_type<T: RepositoryItem>() -> Self {
        Self {
            name: T::NAME,
            list: |registry| Box::pin(list_repo::<T>(registry)),
            get: |registry, key| Box::pin(get_repo::<T>(registry, key)),
            set: |registry, key, value| Box::pin(set_repo::<T>(registry, key, value)),
        }
    }
}

/// Index of per-type shims, keyed by `TypeId`. Held by [`StateRegistry`] so the
/// generic debug surface can address any registered repository by its string
/// name and key.
#[derive(Default)]
pub(crate) struct DebugRegistry {
    repos: RwLock<HashMap<TypeId, DebugRepo>>,
}

impl DebugRegistry {
    /// Create an empty index.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Capture shims for a client-managed type at its registration point.
    pub(crate) fn register<T: RepositoryItem>(&self) {
        self.insert(TypeId::of::<T>(), DebugRepo::for_type::<T>());
    }

    /// Capture shims for every SDK-managed type declared in the migrations, each
    /// carried on its [`RepositoryItemData`](crate::repository::RepositoryItemData)
    /// from the point where the type was still known.
    pub(crate) fn register_migrations(&self, migrations: &RepositoryMigrations) {
        for item in migrations.clone().into_repository_items() {
            self.insert(item.type_id(), item.debug);
        }
    }

    fn insert(&self, type_id: TypeId, repo: DebugRepo) {
        self.repos
            .write()
            .expect("RwLock should not be poisoned")
            .insert(type_id, repo);
    }

    /// Look up the (copyable) shim set for a repository by its type name.
    fn named(&self, type_name: &str) -> Option<DebugRepo> {
        self.repos
            .read()
            .expect("RwLock should not be poisoned")
            .values()
            .find(|repo| repo.name == type_name)
            .copied()
    }

    /// Names of every registered repository.
    fn names(&self) -> Vec<String> {
        self.repos
            .read()
            .expect("RwLock should not be poisoned")
            .values()
            .map(|repo| repo.name.to_string())
            .collect()
    }
}

/// Generic browse over registered repositories, addressed by type name. Backs
/// [`StateDebug`]; bypasses the type-safe public API.
impl StateRegistry {
    /// Names of every registered repository (client- and SDK-managed).
    pub(crate) fn debug_types(&self) -> Vec<String> {
        self.debug.names()
    }

    /// List a repository's values as JSON, addressed by type name. Values only;
    /// the repository API lists values without their keys.
    pub(crate) async fn debug_list(&self, type_name: &str) -> Vec<Value> {
        match self.debug.named(type_name) {
            Some(repo) => (repo.list)(self).await,
            None => Vec::new(),
        }
    }

    /// Read one item by type name and string key, as JSON.
    pub(crate) async fn debug_get(&self, type_name: &str, key: &str) -> Option<Value> {
        let repo = self.debug.named(type_name)?;
        (repo.get)(self, key).await
    }

    /// Write one item by type name and string key. Returns `false` on an unknown
    /// type, a bad key, a value that does not deserialize, or a failed write.
    pub(crate) async fn debug_set(&self, type_name: &str, key: &str, value: Value) -> bool {
        match self.debug.named(type_name) {
            Some(repo) => (repo.set)(self, key, value).await,
            None => false,
        }
    }
}

/// List every item in the `T` repository (client- or SDK-managed) as JSON.
async fn list_repo<T: RepositoryItem>(registry: &StateRegistry) -> Vec<Value> {
    let Ok(repository) = registry.get::<T>() else {
        return Vec::new();
    };
    match repository.list().await {
        Ok(items) => items
            .iter()
            .filter_map(|item| serde_json::to_value(item).ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Read one item from the `T` repository by its string key, as JSON.
async fn get_repo<T: RepositoryItem>(registry: &StateRegistry, key: &str) -> Option<Value> {
    let key = <T::Key as FromStr>::from_str(key).ok()?;
    let value = registry.get::<T>().ok()?.get(key).await.ok().flatten()?;
    serde_json::to_value(&value).ok()
}

/// Write one item to the `T` repository at its string key. Returns `false` on a
/// bad key, a value that does not deserialize to `T`, or a failed write.
async fn set_repo<T: RepositoryItem>(registry: &StateRegistry, key: &str, value: Value) -> bool {
    let Ok(key) = <T::Key as FromStr>::from_str(key) else {
        return false;
    };
    let Ok(value) = serde_json::from_value::<T>(value) else {
        return false;
    };
    match registry.get::<T>() {
        Ok(repository) => repository.set(key, value).await.is_ok(),
        Err(_) => false,
    }
}
