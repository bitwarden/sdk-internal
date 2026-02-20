//! Traits for extracting dependencies from a Client.
//!
//! This module provides:
//! - [`FromClientPart`] trait which enables uniform extraction of dependencies from a [`Client`],
//!   facilitating macro-based generation of `from_client` methods for feature clients.
//! - [`FromClient`] trait which can be derived using `#[derive(FromClient)]` from the
//!   `bitwarden_core_macro` crate to automatically implement `from_client`.

use std::sync::Arc;

use bitwarden_crypto::KeyStore;
#[cfg(feature = "internal")]
use bitwarden_state::repository::{Repository, RepositoryItem};

use super::{ApiProvider, Client};
use crate::key_management::KeyIds;

/// Trait for types that can be constructed from a [`Client`].
///
/// This trait is typically derived using `#[derive(FromClient)]` from
/// the `bitwarden_core_macro` crate, which generates the implementation
/// by extracting all struct fields from the Client using [`FromClientPart`].
///
/// # Example
///
/// ```ignore
/// use bitwarden_core::client::FromClient;
/// use bitwarden_core_macro::FromClient;
///
/// #[derive(FromClient)]
/// pub struct FoldersClient {
///     key_store: KeyStore<KeyIds>,
///     api_config_provider: Arc<dyn ApiProvider>,
///     repository: Arc<dyn Repository<Folder>>,
/// }
///
/// // Usage:
/// let folders_client = FoldersClient::from_client(&client)?;
/// ```
pub trait FromClient: Sized {
    /// Construct this type from a [`Client`] reference.
    fn from_client(client: &Client) -> Result<Self, String>;
}

/// Trait for extracting parts/dependencies from a [`Client`].
///
/// Implemented by [`Client`] for each dependency type that can be extracted. Used internally by
/// `#[derive(FromClient)]` - users should derive [`FromClient`] rather than using this trait
/// directly.
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
