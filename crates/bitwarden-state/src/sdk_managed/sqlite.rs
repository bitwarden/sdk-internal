use std::sync::Arc;

use serde::{de::DeserializeOwned, ser::Serialize};
use tokio::sync::Mutex;

use crate::{
    repository::{RepositoryItem, RepositoryItemData},
    sdk_managed::{Database, DatabaseConfiguration, DatabaseError},
};

// TODO: Use connection pooling with r2d2 and r2d2_sqlite?
#[derive(Clone)]
pub struct SqliteDatabase(Arc<Mutex<rusqlite::Connection>>);
impl Database for SqliteDatabase {
    async fn initialize(
        configuration: DatabaseConfiguration,
        registrations: &[RepositoryItemData],
    ) -> Result<Self, DatabaseError> {
        let DatabaseConfiguration::Sqlite {
            db_name,
            folder_path: mut path,
        } = configuration
        else {
            return Err(DatabaseError::UnsupportedConfiguration(configuration));
        };
        path.set_file_name(format!("{}.sqlite", db_name));

        let mut db = rusqlite::Connection::open(path)?;

        // Set WAL mode for better concurrency
        db.execute("PRAGMA journal_mode = WAL;", [])?;

        let transaction = db.transaction()?;

        for reg in registrations {
            transaction.execute(
                "CREATE TABLE IF NOT EXISTS ?1 (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
                [reg.name],
            )?;
        }

        transaction.commit()?;
        Ok(SqliteDatabase(Arc::new(Mutex::new(db))))
    }

    async fn get<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare("SELECT value FROM ?1 WHERE key = ?2")?;
        let mut rows = stmt.query(rusqlite::params![namespace, key])?;

        if let Some(row) = rows.next()? {
            let value = row.get::<_, String>(0)?;

            Ok(Some(serde_json::from_str(&value)?))
        } else {
            Ok(None)
        }
    }

    async fn list<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        namespace: &str,
    ) -> Result<Vec<T>, DatabaseError> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare("SELECT key, value FROM ?1")?;
        let rows = stmt.query_map(rusqlite::params![namespace], |row| row.get(1))?;

        let mut results = Vec::new();
        for row in rows {
            let value: String = row?;
            let value: T = serde_json::from_str(&value)?;
            results.push(value);
        }

        Ok(results)
    }

    async fn set<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        namespace: &str,
        key: &str,
        value: T,
    ) -> Result<(), DatabaseError> {
        let mut conn = self.0.lock().await;
        let transaction = conn.transaction()?;

        let value = serde_json::to_string(&value)?;

        transaction.execute(
            "INSERT OR REPLACE INTO ?1 (key, value) VALUES (?2, ?3)",
            rusqlite::params![namespace, key, value],
        )?;

        transaction.commit()?;
        Ok(())
    }

    async fn remove(&self, namespace: &str, key: &str) -> Result<(), DatabaseError> {
        let mut conn = self.0.lock().await;
        let transaction = conn.transaction()?;

        transaction.execute(
            "DELETE FROM ?1 WHERE key = ?2",
            rusqlite::params![namespace, key],
        )?;

        transaction.commit()?;
        Ok(())
    }
}
