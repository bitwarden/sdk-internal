//! Trait for extracting dependencies from a Client.
//!
//! This module provides the [`FromClientPart`] trait which enables uniform
//! extraction of dependencies from a [`Client`], facilitating macro-based
//! generation of `from_client` methods for feature clients.

use std::sync::Arc;

use bitwarden_crypto::KeyStore;
#[cfg(feature = "internal")]
use bitwarden_state::repository::{Repository, RepositoryItem};

use super::{ApiProvider, Client};
use crate::key_management::KeyIds;

/// Trait for extracting parts/dependencies from a [`Client`].
///
/// Implemented by [`Client`] for each dependency type that can be extracted.
/// This enables macro-based generation of `from_client` methods.
///
/// # Example
///
/// ```ignore
/// use bitwarden_core::client::FromClientPart;
///
/// impl MyFeatureClient {
///     pub fn from_client(client: &Client) -> Result<Self, Error> {
///         Ok(Self {
///             key_store: client.get_part()?,
///             api_provider: client.get_part()?,
///             repository: client.get_part()?,
///         })
///     }
/// }
/// ```
pub trait FromClientPart<T> {
    /// The error type returned when extraction fails.
    type Error;

    /// Extract a dependency of type `T` from self.
    fn get_part(&self) -> Result<T, Self::Error>;
}

impl FromClientPart<KeyStore<KeyIds>> for Client {
    type Error = std::convert::Infallible;

    fn get_part(&self) -> Result<KeyStore<KeyIds>, Self::Error> {
        Ok(self.internal.get_key_store().clone())
    }
}

impl FromClientPart<Arc<dyn ApiProvider>> for Client {
    type Error = std::convert::Infallible;

    fn get_part(&self) -> Result<Arc<dyn ApiProvider>, Self::Error> {
        Ok(Arc::new(self.internal.clone()))
    }
}

#[cfg(feature = "internal")]
impl<T: RepositoryItem> FromClientPart<Arc<dyn Repository<T>>> for Client {
    type Error = bitwarden_state::registry::StateRegistryError;

    fn get_part(&self) -> Result<Arc<dyn Repository<T>>, Self::Error> {
        self.platform().state().get::<T>()
    }
}
