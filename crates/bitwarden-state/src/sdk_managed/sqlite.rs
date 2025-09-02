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

impl SqliteDatabase {
    fn initialize_internal(
        mut db: rusqlite::Connection,
        registrations: &[RepositoryItemData],
    ) -> Result<Self, DatabaseError> {
        // Set WAL mode for better concurrency
        db.pragma_update(None, "journal_mode", "WAL")?;

        let transaction = db.transaction()?;

        for reg in registrations {
            // SAFETY: SQLite tables cannot use ?, but `reg.name()` is not user controlled and
            // is validated to only contain valid characters, so it's safe to
            // interpolate here.

            transaction.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {} (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
                    reg.name(),
                ),
                [],
            )?;
        }

        transaction.commit()?;
        Ok(SqliteDatabase(Arc::new(Mutex::new(db))))
    }
}

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
        path.set_file_name(format!("{db_name}.sqlite"));

        let db = rusqlite::Connection::open(path)?;
        Self::initialize_internal(db, registrations)
    }

    async fn get<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        let conn = self.0.lock().await;

        // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
        // validated to only contain valid characters, so it's safe to interpolate here.
        let mut stmt = conn.prepare(&format!("SELECT value FROM {} WHERE key = ?1", T::NAME))?;
        let mut rows = stmt.query(rusqlite::params![key])?;

        if let Some(row) = rows.next()? {
            let value = row.get::<_, String>(0)?;

            Ok(Some(serde_json::from_str(&value)?))
        } else {
            Ok(None)
        }
    }

    async fn list<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<Vec<T>, DatabaseError> {
        let conn = self.0.lock().await;

        // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
        // validated to only contain valid characters, so it's safe to interpolate here.
        let mut stmt = conn.prepare(&format!("SELECT key, value FROM {}", T::NAME))?;
        let rows = stmt.query_map([], |row| row.get(1))?;

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
        key: &str,
        value: T,
    ) -> Result<(), DatabaseError> {
        let mut conn = self.0.lock().await;
        let transaction = conn.transaction()?;

        let value = serde_json::to_string(&value)?;

        // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
        // validated to only contain valid characters, so it's safe to interpolate here.
        transaction.execute(
            &format!(
                "INSERT OR REPLACE INTO {} (key, value) VALUES (?1, ?2)",
                T::NAME,
            ),
            rusqlite::params![key, value],
        )?;

        transaction.commit()?;
        Ok(())
    }

    async fn remove<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<(), DatabaseError> {
        let mut conn = self.0.lock().await;
        let transaction = conn.transaction()?;

        // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
        // validated to only contain valid characters, so it's safe to interpolate here.
        transaction.execute(
            &format!("DELETE FROM {} WHERE key = ?1", T::NAME),
            rusqlite::params![key],
        )?;

        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register_repository_item;

    #[tokio::test]
    async fn test_sqlite_integration() {
        let db = rusqlite::Connection::open_in_memory().unwrap();

        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct TestA(usize);
        register_repository_item!(TestA, "TestItem_A");

        let registrations = vec![TestA::data()];

        let db = SqliteDatabase::initialize_internal(db, &registrations).unwrap();

        assert_eq!(db.list::<TestA>().await.unwrap(), Vec::<TestA>::new());

        db.set("key1", TestA(42)).await.unwrap();
        assert_eq!(db.get::<TestA>("key1").await.unwrap(), Some(TestA(42)));

        db.remove::<TestA>("key1").await.unwrap();

        assert_eq!(db.get::<TestA>("key1").await.unwrap(), None);
    }
}
