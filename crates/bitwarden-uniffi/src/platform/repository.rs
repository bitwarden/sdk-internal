use std::sync::Arc;

pub struct UniffiRepositoryBridge<T>(pub T);

impl<T: ?Sized> UniffiRepositoryBridge<Arc<T>> {
    pub fn new(store: Arc<T>) -> Arc<Self> {
        Arc::new(UniffiRepositoryBridge(store))
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for UniffiRepositoryBridge<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum RepositoryError {
    #[error("Internal error: {0}")]
    Internal(String),
}

// Need to implement this From<> impl in order to handle unexpected callback errors.  See the
// following page in the Uniffi user guide:
// <https://mozilla.github.io/uniffi-rs/foreign_traits.html#error-handling>
impl From<uniffi::UnexpectedUniFFICallbackError> for RepositoryError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Internal(e.reason)
    }
}

impl From<RepositoryError> for bitwarden_state::repository::RepositoryError {
    fn from(e: RepositoryError) -> Self {
        match e {
            RepositoryError::Internal(msg) => Self::Internal(msg),
        }
    }
}

/// This macro creates a Uniffi repository trait and its implementation for the
/// [bitwarden_state::repository::Repository] trait
macro_rules! create_uniffi_repository {
    ($name:ident, $ty:ty) => {
        #[uniffi::export(with_foreign)]
        #[async_trait::async_trait]
        pub trait $name: Send + Sync {
            async fn get(
                &self,
                id: String,
            ) -> Result<Option<$ty>, $crate::platform::repository::RepositoryError>;
            async fn list(&self)
            -> Result<Vec<$ty>, $crate::platform::repository::RepositoryError>;
            async fn set(
                &self,
                id: String,
                value: $ty,
            ) -> Result<(), $crate::platform::repository::RepositoryError>;
            async fn remove(
                &self,
                id: String,
            ) -> Result<(), $crate::platform::repository::RepositoryError>;

            async fn has(
                &self,
                id: String,
            ) -> Result<bool, $crate::platform::repository::RepositoryError>;
        }

        #[async_trait::async_trait]
        impl bitwarden_state::repository::Repository<$ty>
            for $crate::platform::repository::UniffiRepositoryBridge<Arc<dyn $name>>
        {
            async fn get(
                &self,
                key: String,
            ) -> Result<Option<$ty>, bitwarden_state::repository::RepositoryError> {
                self.0.get(key).await.map_err(Into::into)
            }
            async fn list(&self) -> Result<Vec<$ty>, bitwarden_state::repository::RepositoryError> {
                self.0.list().await.map_err(Into::into)
            }
            async fn set(
                &self,
                key: String,
                value: $ty,
            ) -> Result<(), bitwarden_state::repository::RepositoryError> {
                self.0.set(key, value).await.map_err(Into::into)
            }
            async fn remove(
                &self,
                key: String,
            ) -> Result<(), bitwarden_state::repository::RepositoryError> {
                self.0.remove(key).await.map_err(Into::into)
            }
        }
    };
}
pub(super) use create_uniffi_repository;
