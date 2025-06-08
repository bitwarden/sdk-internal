use std::sync::Arc;

use tokio::sync::Mutex;

use crate::{
    repository::RepositoryItemData,
    sdk_managed::{Database, DatabaseError},
};

// TODO: Use connection pooling with r2d2 and r2d2_sqlite?
#[derive(Clone)]
pub struct SqliteDatabase(Arc<Mutex<rusqlite::Connection>>);
impl Database for SqliteDatabase {
    async fn initialize(registrations: &[RepositoryItemData]) -> Result<Self, DatabaseError> {
        let mut db = rusqlite::Connection::open_in_memory()?;

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

    async fn get(&self, namespace: &str, key: &str) -> Result<Option<String>, DatabaseError> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare("SELECT value FROM ?1 WHERE key = ?2")?;
        let mut rows = stmt.query(rusqlite::params![namespace, key])?;

        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    async fn list(&self, namespace: &str) -> Result<Vec<String>, DatabaseError> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare("SELECT key, value FROM ?1")?;
        let rows = stmt.query_map(rusqlite::params![namespace], |row| row.get(1))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }

    async fn set(&self, namespace: &str, key: &str, value: String) -> Result<(), DatabaseError> {
        let mut conn = self.0.lock().await;
        let transaction = conn.transaction()?;

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
