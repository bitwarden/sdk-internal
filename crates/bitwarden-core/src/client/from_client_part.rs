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

use super::Client;
use crate::{client::ApiConfigurations, key_management::KeyIds};

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
///     api_configurations: Arc<ApiConfigurations>,
///     repository: Arc<dyn Repository<Folder>>,
/// }
///
/// // Usage:
/// let folders_client = FoldersClient::from_client(&client);
/// ```
pub trait FromClient: Sized {
    /// Construct this type from a [`Client`] reference.
    fn from_client(client: &Client) -> Self;
}

/// Trait for extracting parts/dependencies from a [`Client`].
///
/// Implemented by [`Client`] for each dependency type that can be extracted. Used internally by
/// `#[derive(FromClient)]` - users should derive [`FromClient`] rather than using this trait
/// directly.
pub trait FromClientPart<T> {
    /// Extract a dependency of type `T` from self.
    fn get_part(&self) -> T;
}

impl FromClientPart<KeyStore<KeyIds>> for Client {
    fn get_part(&self) -> KeyStore<KeyIds> {
        self.internal.get_key_store().clone()
    }
}

impl FromClientPart<Arc<ApiConfigurations>> for Client {
    fn get_part(&self) -> Arc<ApiConfigurations> {
        self.internal.get_api_configurations()
    }
}

#[cfg(feature = "internal")]
impl<T: RepositoryItem> FromClientPart<Option<Arc<dyn Repository<T>>>> for Client {
    fn get_part(&self) -> Option<Arc<dyn Repository<T>>> {
        self.platform().state().get::<T>().ok()
    }
}
