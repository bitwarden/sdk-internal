use std::sync::Arc;

use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::repository::{Repository, RepositoryError, RepositoryItem, RepositoryMigrations};

mod configuration;
pub use configuration::DatabaseConfiguration;

#[cfg(target_arch = "wasm32")]
mod indexed_db;
#[cfg(target_arch = "wasm32")]
pub(super) type SystemDatabase = indexed_db::IndexedDbDatabase;
#[cfg(target_arch = "wasm32")]
type InternalError = ::indexed_db::Error<indexed_db::IndexedDbInternalError>;

#[cfg(not(target_arch = "wasm32"))]
mod sqlite;
#[cfg(not(target_arch = "wasm32"))]
pub(super) type SystemDatabase = sqlite::SqliteDatabase;
#[cfg(not(target_arch = "wasm32"))]
type InternalError = ::rusqlite::Error;

#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Database not supported on this platform: {0:?}")]
    UnsupportedConfiguration(DatabaseConfiguration),

    #[error(transparent)]
    ThreadBoundRunner(#[from] bitwarden_threading::CallError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("JS error: {0}")]
    JS(String),

    #[error(transparent)]
    Internal(#[from] InternalError),
}

pub trait Database {
    async fn initialize(
        configuration: DatabaseConfiguration,
        registrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError>
    where
        Self: Sized;

    async fn get<T: RepositoryItem>(&self, key: &str) -> Result<Option<T>, DatabaseError>;

    async fn list<T: RepositoryItem>(&self) -> Result<Vec<T>, DatabaseError>;

    async fn set<T: RepositoryItem>(&self, key: &str, value: T) -> Result<(), DatabaseError>;

    async fn remove<T: RepositoryItem>(&self, key: &str) -> Result<(), DatabaseError>;
}

struct DBRepository<T: RepositoryItem> {
    database: SystemDatabase,
    _marker: std::marker::PhantomData<T>,
}

#[async_trait::async_trait]
impl<V: RepositoryItem> Repository<V> for DBRepository<V> {
    async fn get(&self, key: String) -> Result<Option<V>, RepositoryError> {
        let value = self.database.get::<V>(&key).await?;
        Ok(value)
    }
    async fn list(&self) -> Result<Vec<V>, RepositoryError> {
        let values = self.database.list::<V>().await?;
        Ok(values)
    }
    async fn set(&self, key: String, value: V) -> Result<(), RepositoryError> {
        Ok(self.database.set::<V>(&key, value).await?)
    }
    async fn remove(&self, key: String) -> Result<(), RepositoryError> {
        Ok(self.database.remove::<V>(&key).await?)
    }
}

impl SystemDatabase {
    pub(super) fn get_repository<V: RepositoryItem>(&self) -> Arc<dyn Repository<V>> {
        Arc::new(DBRepository {
            database: self.clone(),
            _marker: std::marker::PhantomData,
        })
    }
}
