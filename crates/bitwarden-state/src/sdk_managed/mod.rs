use bitwarden_error::bitwarden_error;
use serde::{de::DeserializeOwned, ser::Serialize};
use thiserror::Error;

use crate::repository::{Repository, RepositoryError, RepositoryItem, RepositoryItemData};

#[cfg(target_arch = "wasm32")]
mod indexed_db;
#[cfg(target_arch = "wasm32")]
pub(super) type SystemDatabase = indexed_db::IndexedDbDatabase;
#[cfg(target_arch = "wasm32")]
type InternalError = ::indexed_db::Error<std::convert::Infallible>;

#[cfg(not(target_arch = "wasm32"))]
mod sqlite;
#[cfg(not(target_arch = "wasm32"))]
pub(super) type SystemDatabase = sqlite::SqliteDatabase;
#[cfg(not(target_arch = "wasm32"))]
type InternalError = ::rusqlite::Error;

#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    ThreadBoundRunner(#[from] bitwarden_threading::CallError),

    #[error(transparent)]
    Internal(#[from] InternalError),
}

pub trait Database {
    async fn initialize(registrations: &[RepositoryItemData]) -> Result<Self, DatabaseError>
    where
        Self: Sized;

    async fn get(&self, namespace: &str, key: &str) -> Result<Option<String>, DatabaseError>;

    async fn list(&self, namespace: &str) -> Result<Vec<String>, DatabaseError>;

    async fn set(&self, namespace: &str, key: &str, value: String) -> Result<(), DatabaseError>;

    async fn remove(&self, namespace: &str, key: &str) -> Result<(), DatabaseError>;
}

struct DBRepository<T: RepositoryItem> {
    database: SystemDatabase,
    _marker: std::marker::PhantomData<T>,
}

#[async_trait::async_trait]
impl<V: RepositoryItem + Serialize + DeserializeOwned> Repository<V> for DBRepository<V> {
    async fn get(&self, key: String) -> Result<Option<V>, RepositoryError> {
        let value = self.database.get(V::NAME, &key).await?;
        Ok(value.map(|v| serde_json::from_str(&v)).transpose()?)
    }
    async fn list(&self) -> Result<Vec<V>, RepositoryError> {
        let values = self.database.list(V::NAME).await?;
        let mut results = Vec::new();
        for value in values {
            results.push(serde_json::from_str(&value)?);
        }
        Ok(results)
    }
    async fn set(&self, key: String, value: V) -> Result<(), RepositoryError> {
        let value_str = serde_json::to_string(&value)?;
        Ok(self.database.set(V::NAME, &key, value_str).await?)
    }
    async fn remove(&self, key: String) -> Result<(), RepositoryError> {
        Ok(self.database.remove(V::NAME, &key).await?)
    }
}

impl SystemDatabase {
    pub(super) fn get_repository<V: RepositoryItem + Serialize + DeserializeOwned>(
        &self,
    ) -> Result<impl Repository<V>, DatabaseError> {
        Ok(DBRepository {
            database: self.clone(),
            _marker: std::marker::PhantomData,
        })
    }
}
