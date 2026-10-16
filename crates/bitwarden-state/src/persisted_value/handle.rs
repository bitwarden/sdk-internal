//! Persisted value types for type-safe access to individual persisted values.

use std::{marker::PhantomData, sync::Arc};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::PersistedValueKey;
use crate::{persist::Persist, sdk_managed::DatabaseError};

/// Internal persisted value as stored in the SDK-managed database.
///
/// This type wraps a JSON value for flexible storage. Users should not work with
/// this type directly - use the [`PersistedValue<K>`] handle via `StateClient::value()` instead,
/// which provides type-safe access.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedValueItem(pub(crate) serde_json::Value);

crate::register_repository_item!(String => PersistedValueItem, "PersistedValue");

#[doc(hidden)]
#[async_trait::async_trait]
pub trait PersistedValueTrait<T: Persist>: Send + Sync {
    async fn get(&self) -> Result<Option<T>, PersistedValueError>;
    async fn set(&self, value: T) -> Result<(), PersistedValueError>;
    async fn remove(&self) -> Result<(), PersistedValueError>;
}

// A macro so `tracing` resolves `file!`/`line!` per call site; a function would collapse every
// event onto its own line. Records the value name only, never the stored value.
macro_rules! trace_failure {
    ($operation:literal, $name:expr, $error:expr) => {
        tracing::error!(
            persisted_value = $name,
            operation = $operation,
            error = %$error,
            "persisted value operation failed"
        )
    };
}

/// A handle to a single persisted value in storage.
///
/// This type provides async methods to get, update, and delete the persisted value.
/// Obtained via `StateClient::value()`, or injected with `#[derive(FromClient)]`.
///
/// Every failed operation is logged with `tracing::error!`, so callers that discard an error
/// don't need to log it themselves. `try_get` finding no value is not a failure.
///
/// # Example
/// ```rust,ignore
/// use bitwarden_state::register_persisted_value;
///
/// register_persisted_value!(THEME: String = "theme");
///
/// let value = client.platform().state().value::<THEME>();
///
/// // Get the current value
/// let current: Option<String> = value.try_get().await?;
///
/// // Update the value
/// value.set("dark".to_string()).await?;
///
/// // Delete the value
/// value.remove().await?;
/// ```
pub struct PersistedValue<K: PersistedValueKey> {
    pub(crate) backend: Arc<dyn PersistedValueTrait<K::Value>>,
    _marker: PhantomData<K>,
}

// Implemented by hand because `#[derive(Clone)]` would require `K: Clone`.
impl<K: PersistedValueKey> Clone for PersistedValue<K> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            _marker: PhantomData,
        }
    }
}

impl<K: PersistedValueKey, B: PersistedValueTrait<K::Value> + 'static> From<Arc<B>>
    for PersistedValue<K>
{
    fn from(backend: Arc<B>) -> Self {
        Self::new(backend)
    }
}

impl<K: PersistedValueKey> PersistedValue<K> {
    /// Create a new persisted value handle from a backend.
    ///
    /// The backend is already bound to a single key, so it decides where the value is stored.
    pub fn new(backend: Arc<dyn PersistedValueTrait<K::Value>>) -> Self {
        Self {
            backend,
            _marker: PhantomData,
        }
    }

    /// Get the current value, failing with [`PersistedValueError::ValueNotFound`] if it doesn't
    /// exist in storage. Use [`Self::try_get`] where absence is an expected outcome.
    pub async fn get(&self) -> Result<K::Value, PersistedValueError> {
        self.backend
            .get()
            .await
            .and_then(|value| value.ok_or(PersistedValueError::ValueNotFound(K::NAME)))
            .inspect_err(|e| trace_failure!("get", K::NAME, e))
    }

    /// Get the current value.
    ///
    /// Returns `None` if the value doesn't exist in storage.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails, which may indicate:
    /// - Schema evolution problems (type definition changed)
    /// - Data corruption
    /// - Type mismatch (two keys sharing a key name)
    pub async fn try_get(&self) -> Result<Option<K::Value>, PersistedValueError> {
        self.backend
            .get()
            .await
            .inspect_err(|e| trace_failure!("try_get", K::NAME, e))
    }

    /// Update (or create) this persisted value with a new value.
    pub async fn set(&self, value: K::Value) -> Result<(), PersistedValueError> {
        self.backend
            .set(value)
            .await
            .inspect_err(|e| trace_failure!("set", K::NAME, e))
    }

    /// Delete this persisted value from storage.
    pub async fn remove(&self) -> Result<(), PersistedValueError> {
        self.backend
            .remove()
            .await
            .inspect_err(|e| trace_failure!("remove", K::NAME, e))
    }
}

/// Errors that can occur when working with persisted values.
#[derive(Debug, Error)]
pub enum PersistedValueError {
    /// The value has never been written.
    #[error("Persisted value '{0}' not found")]
    ValueNotFound(&'static str),
    /// The database was closed by `StateRegistry::wipe()`.
    #[error("Persisted value storage is closed")]
    Closed,
    /// Any other failure. Never contains the stored value.
    #[error("{0}")]
    Internal(String),
}

impl From<DatabaseError> for PersistedValueError {
    fn from(e: DatabaseError) -> Self {
        match e {
            DatabaseError::Closed => Self::Closed,
            other => Self::Internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{register_persisted_value, registry::StateRegistry};

    register_persisted_value!(THEME: String = "persisted_value_test_theme");

    #[tokio::test]
    async fn test_get_fails_when_absent() {
        let value = StateRegistry::new_with_memory_db().value::<THEME>();

        assert!(matches!(
            value.get().await,
            Err(PersistedValueError::ValueNotFound(
                "persisted_value_test_theme"
            ))
        ));
        assert_eq!(value.try_get().await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_deserialization_error_does_not_contain_stored_value() {
        register_persisted_value!(AS_STRING: String = "persisted_value_test_aliased");
        register_persisted_value!(AS_NUMBER: u32 = "persisted_value_test_aliased");

        let registry = StateRegistry::new_with_memory_db();
        registry
            .value::<AS_STRING>()
            .set("secret-token".to_string())
            .await
            .unwrap();

        let error = registry.value::<AS_NUMBER>().get().await.unwrap_err();

        assert!(matches!(error, PersistedValueError::Internal(_)));
        assert!(!error.to_string().contains("secret-token"));
    }
}
