use std::sync::Arc;

use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::repository::{Repository, RepositoryError, RepositoryItem, RepositoryMigrations};

mod configuration;
pub use configuration::DatabaseConfiguration;

#[cfg(target_arch = "wasm32")]
mod indexed_db;
pub(super) mod memory;
#[cfg(not(target_arch = "wasm32"))]
mod sqlite;

#[derive(Clone)]
pub(super) enum SystemDatabase {
    Memory(memory::MemoryDatabase),
    #[cfg(not(target_arch = "wasm32"))]
    Sqlite(sqlite::SqliteDatabase),
    #[cfg(target_arch = "wasm32")]
    IndexedDb(indexed_db::IndexedDbDatabase),
}

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

    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(not(target_arch = "wasm32"))]
impl From<rusqlite::Error> for DatabaseError {
    fn from(e: rusqlite::Error) -> Self {
        DatabaseError::Internal(e.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<indexed_db::Error<indexed_db::IndexedDbInternalError>> for DatabaseError {
    fn from(e: indexed_db::Error<indexed_db::IndexedDbInternalError>) -> Self {
        DatabaseError::Internal(e.to_string())
    }
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

    async fn set_bulk<T: RepositoryItem>(
        &self,
        values: Vec<(String, T)>,
    ) -> Result<(), DatabaseError>;

    async fn remove<T: RepositoryItem>(&self, key: &str) -> Result<(), DatabaseError>;

    async fn remove_bulk<T: RepositoryItem>(&self, keys: Vec<String>) -> Result<(), DatabaseError>;

    async fn remove_all<T: RepositoryItem>(&self) -> Result<(), DatabaseError>;
}

impl Database for SystemDatabase {
    async fn initialize(
        configuration: DatabaseConfiguration,
        registrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        match &configuration {
            DatabaseConfiguration::Memory => Ok(SystemDatabase::Memory(
                memory::MemoryDatabase::initialize(configuration, registrations).await?,
            )),
            #[cfg(not(target_arch = "wasm32"))]
            DatabaseConfiguration::Sqlite { .. } => Ok(SystemDatabase::Sqlite(
                sqlite::SqliteDatabase::initialize(configuration, registrations).await?,
            )),
            #[cfg(target_arch = "wasm32")]
            DatabaseConfiguration::IndexedDb { .. } => Ok(SystemDatabase::IndexedDb(
                indexed_db::IndexedDbDatabase::initialize(configuration, registrations).await?,
            )),
            #[allow(unreachable_patterns)]
            _ => Err(DatabaseError::UnsupportedConfiguration(configuration)),
        }
    }

    async fn get<T: RepositoryItem>(&self, key: &str) -> Result<Option<T>, DatabaseError> {
        match self {
            SystemDatabase::Memory(db) => db.get::<T>(key).await,
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => db.get::<T>(key).await,
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => db.get::<T>(key).await,
        }
    }

    async fn list<T: RepositoryItem>(&self) -> Result<Vec<T>, DatabaseError> {
        match self {
            SystemDatabase::Memory(db) => db.list::<T>().await,
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => db.list::<T>().await,
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => db.list::<T>().await,
        }
    }

    async fn set<T: RepositoryItem>(&self, key: &str, value: T) -> Result<(), DatabaseError> {
        match self {
            SystemDatabase::Memory(db) => db.set::<T>(key, value).await,
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => db.set::<T>(key, value).await,
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => db.set::<T>(key, value).await,
        }
    }

    async fn set_bulk<T: RepositoryItem>(
        &self,
        values: Vec<(String, T)>,
    ) -> Result<(), DatabaseError> {
        match self {
            SystemDatabase::Memory(db) => db.set_bulk::<T>(values).await,
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => db.set_bulk::<T>(values).await,
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => db.set_bulk::<T>(values).await,
        }
    }

    async fn remove<T: RepositoryItem>(&self, key: &str) -> Result<(), DatabaseError> {
        match self {
            SystemDatabase::Memory(db) => db.remove::<T>(key).await,
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => db.remove::<T>(key).await,
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => db.remove::<T>(key).await,
        }
    }

    async fn remove_bulk<T: RepositoryItem>(&self, keys: Vec<String>) -> Result<(), DatabaseError> {
        match self {
            SystemDatabase::Memory(db) => db.remove_bulk::<T>(keys).await,
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => db.remove_bulk::<T>(keys).await,
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => db.remove_bulk::<T>(keys).await,
        }
    }

    async fn remove_all<T: RepositoryItem>(&self) -> Result<(), DatabaseError> {
        match self {
            SystemDatabase::Memory(db) => db.remove_all::<T>().await,
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => db.remove_all::<T>().await,
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => db.remove_all::<T>().await,
        }
    }
}

struct DBRepository<T: RepositoryItem> {
    database: SystemDatabase,
    _marker: std::marker::PhantomData<T>,
}

#[async_trait::async_trait]
impl<V: RepositoryItem> Repository<V> for DBRepository<V> {
    async fn get(&self, key: V::Key) -> Result<Option<V>, RepositoryError> {
        let key = key.to_string();
        let value = self.database.get::<V>(&key).await?;
        Ok(value)
    }
    async fn list(&self) -> Result<Vec<V>, RepositoryError> {
        let values = self.database.list::<V>().await?;
        Ok(values)
    }
    async fn set(&self, key: V::Key, value: V) -> Result<(), RepositoryError> {
        let key = key.to_string();
        Ok(self.database.set::<V>(&key, value).await?)
    }
    async fn set_bulk(&self, values: Vec<(V::Key, V)>) -> Result<(), RepositoryError> {
        let values = values
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        Ok(self.database.set_bulk::<V>(values).await?)
    }
    async fn remove(&self, key: V::Key) -> Result<(), RepositoryError> {
        let key = key.to_string();
        Ok(self.database.remove::<V>(&key).await?)
    }
    async fn remove_bulk(&self, keys: Vec<V::Key>) -> Result<(), RepositoryError> {
        let keys = keys.into_iter().map(|k| k.to_string()).collect();
        Ok(self.database.remove_bulk::<V>(keys).await?)
    }
    async fn remove_all(&self) -> Result<(), RepositoryError> {
        Ok(self.database.remove_all::<V>().await?)
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
