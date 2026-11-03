use serde::{Serialize, de::DeserializeOwned};

/// A value that can be persisted to SDK-managed storage.
///
/// This exists purely as a shorthand for the bounds every stored value must satisfy, so they
/// don't have to be repeated at every use site. It carries no behavior and is implemented
/// automatically for any type that meets them.
pub trait Persist: Serialize + DeserializeOwned + Send + Sync + 'static {}

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> Persist for T {}
