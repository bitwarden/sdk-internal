use serde::{Serialize, de::DeserializeOwned};

/// A value that can be persisted to SDK-managed storage.
///
/// This is a marker for the bounds every stored value must satisfy, and is implemented
/// automatically for any type that meets them.
pub trait PersistentValue: Serialize + DeserializeOwned + Send + Sync + 'static {}

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> PersistentValue for T {}
