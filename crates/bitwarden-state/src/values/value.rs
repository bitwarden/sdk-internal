//! The [`Value`] handle and the storage it reads and writes.

use std::{marker::PhantomData, sync::Arc};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ValueKey;
use crate::{
    registry::StateRegistryError,
    repository::{RepositoryError, RepositoryTrait},
};

/// Every value lives in one storage table, keyed by the value's name and holding its JSON.
///
/// The `"Setting"` name is load-bearing: it is the live SQLite table and IndexedDB object store
/// holding authentication tokens, the session-protected user key, and account crypto state.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValueItem(pub(crate) serde_json::Value);

crate::register_repository_item!(String => ValueItem, "Setting");

/// A handle to the single value identified by `K`. Cloning shares the same storage.
///
/// Obtained from `StateClient::value::<K>()`, or injected into a client with
/// `#[derive(FromClient)]`.
pub struct Value<K: ValueKey> {
    storage: Arc<dyn RepositoryTrait<ValueItem>>,
    _marker: PhantomData<fn() -> K>,
}

impl<K: ValueKey> Clone for Value<K> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            _marker: PhantomData,
        }
    }
}

impl<K: ValueKey> std::fmt::Debug for Value<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Value").field(&K::NAME).finish()
    }
}

impl<K: ValueKey> Value<K> {
    pub(crate) fn new(storage: Arc<dyn RepositoryTrait<ValueItem>>) -> Self {
        Self {
            storage,
            _marker: PhantomData,
        }
    }

    /// Read the value, failing with [`ValueError::NotFound`] if it has never been written. Use
    /// [`Self::get_opt`] where absence is an expected outcome.
    pub async fn get(&self) -> Result<K::Value, ValueError> {
        self.get_opt().await?.ok_or(ValueError::NotFound)
    }

    /// Read the value, or `None` if it has never been written.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails, which may indicate:
    /// - Schema evolution problems (type definition changed)
    /// - Data corruption
    /// - Type mismatch (two keys sharing a storage name)
    pub async fn get_opt(&self) -> Result<Option<K::Value>, ValueError> {
        match self.storage.get(K::NAME.to_string()).await? {
            Some(item) => Ok(Some(serde_json::from_value(item.0)?)),
            None => Ok(None),
        }
    }

    /// Write the value, replacing anything already stored under this key.
    pub async fn set(&self, value: K::Value) -> Result<(), ValueError> {
        let item = ValueItem(serde_json::to_value(&value)?);
        self.storage.set(K::NAME.to_string(), item).await?;
        Ok(())
    }

    /// Remove the value from storage. Removing an absent value is not an error.
    pub async fn remove(&self) -> Result<(), ValueError> {
        self.storage.remove(K::NAME.to_string()).await?;
        Ok(())
    }
}

/// Errors that can occur when working with values.
#[derive(Debug, Error)]
pub enum ValueError {
    /// The value has never been written.
    #[error("Value not found")]
    NotFound,
    /// Failed to serialize/deserialize the value
    #[error("Failed to serialize/deserialize value: {0}")]
    Json(#[from] serde_json::Error),
    /// Storage operation failed
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    /// State registry operation failed
    #[error(transparent)]
    Registry(#[from] StateRegistryError),
}
