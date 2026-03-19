use std::sync::Arc;

use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::repository::{Repository, RepositoryError, RepositoryItem, RepositoryMigrations};

mod configuration;
pub use configuration::DatabaseConfiguration;

#[cfg(target_arch = "wasm32")]
mod indexed_db;

#[cfg(not(target_arch = "wasm32"))]
mod sqlite;

mod memory;

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
impl From<::indexed_db::Error<indexed_db::IndexedDbInternalError>> for DatabaseError {
    fn from(e: ::indexed_db::Error<indexed_db::IndexedDbInternalError>) -> Self {
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

#[derive(Clone)]
pub(super) enum SystemDatabase {
    #[cfg(not(target_arch = "wasm32"))]
    Sqlite(sqlite::SqliteDatabase),
    #[cfg(target_arch = "wasm32")]
    IndexedDb(indexed_db::IndexedDbDatabase),
    Memory(memory::MemoryDatabase),
}

struct DBRepository<T: RepositoryItem> {
    database: SystemDatabase,
    _marker: std::marker::PhantomData<T>,
}

#[async_trait::async_trait]
impl<V: RepositoryItem> Repository<V> for DBRepository<V> {
    async fn get(&self, key: V::Key) -> Result<Option<V>, RepositoryError> {
        let key = key.to_string();
        match &self.database {
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => Ok(db.get::<V>(&key).await?),
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => Ok(db.get::<V>(&key).await?),
            SystemDatabase::Memory(db) => Ok(db.get::<V>(&key).await?),
        }
    }
    async fn list(&self) -> Result<Vec<V>, RepositoryError> {
        match &self.database {
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => Ok(db.list::<V>().await?),
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => Ok(db.list::<V>().await?),
            SystemDatabase::Memory(db) => Ok(db.list::<V>().await?),
        }
    }
    async fn set(&self, key: V::Key, value: V) -> Result<(), RepositoryError> {
        let key = key.to_string();
        match &self.database {
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => Ok(db.set::<V>(&key, value).await?),
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => Ok(db.set::<V>(&key, value).await?),
            SystemDatabase::Memory(db) => Ok(db.set::<V>(&key, value).await?),
        }
    }
    async fn set_bulk(&self, values: Vec<(V::Key, V)>) -> Result<(), RepositoryError> {
        let values = values
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        match &self.database {
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => Ok(db.set_bulk::<V>(values).await?),
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => Ok(db.set_bulk::<V>(values).await?),
            SystemDatabase::Memory(db) => Ok(db.set_bulk::<V>(values).await?),
        }
    }
    async fn remove(&self, key: V::Key) -> Result<(), RepositoryError> {
        let key = key.to_string();
        match &self.database {
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => Ok(db.remove::<V>(&key).await?),
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => Ok(db.remove::<V>(&key).await?),
            SystemDatabase::Memory(db) => Ok(db.remove::<V>(&key).await?),
        }
    }
    async fn remove_bulk(&self, keys: Vec<V::Key>) -> Result<(), RepositoryError> {
        let keys = keys.into_iter().map(|k| k.to_string()).collect();
        match &self.database {
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => Ok(db.remove_bulk::<V>(keys).await?),
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => Ok(db.remove_bulk::<V>(keys).await?),
            SystemDatabase::Memory(db) => Ok(db.remove_bulk::<V>(keys).await?),
        }
    }
    async fn remove_all(&self) -> Result<(), RepositoryError> {
        match &self.database {
            #[cfg(not(target_arch = "wasm32"))]
            SystemDatabase::Sqlite(db) => Ok(db.remove_all::<V>().await?),
            #[cfg(target_arch = "wasm32")]
            SystemDatabase::IndexedDb(db) => Ok(db.remove_all::<V>().await?),
            SystemDatabase::Memory(db) => Ok(db.remove_all::<V>().await?),
        }
    }
}

impl SystemDatabase {
    pub(super) fn new_memory() -> Self {
        SystemDatabase::Memory(memory::MemoryDatabase::new())
    }

    pub(super) fn get_repository<V: RepositoryItem>(&self) -> Arc<dyn Repository<V>> {
        Arc::new(DBRepository {
            database: self.clone(),
            _marker: std::marker::PhantomData,
        })
    }

    pub(super) async fn initialize(
        configuration: DatabaseConfiguration,
        registrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        match configuration {
            #[cfg(not(target_arch = "wasm32"))]
            DatabaseConfiguration::Sqlite { .. } => Ok(SystemDatabase::Sqlite(
                sqlite::SqliteDatabase::initialize(configuration, registrations).await?,
            )),
            #[cfg(target_arch = "wasm32")]
            DatabaseConfiguration::IndexedDb { .. } => Ok(SystemDatabase::IndexedDb(
                indexed_db::IndexedDbDatabase::initialize(configuration, registrations).await?,
            )),
            DatabaseConfiguration::Memory => Ok(SystemDatabase::Memory(
                memory::MemoryDatabase::initialize(configuration, registrations).await?,
            )),
            #[allow(unreachable_patterns)]
            other => Err(DatabaseError::UnsupportedConfiguration(other)),
        }
    }
}
