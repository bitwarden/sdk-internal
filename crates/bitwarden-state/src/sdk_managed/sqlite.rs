use std::sync::Arc;

use serde::{de::DeserializeOwned, ser::Serialize};
use tokio::sync::Mutex;

use crate::{
    repository::{
        RepositoryItem, RepositoryMigrationStep, RepositoryMigrations, validate_registry_name,
    },
    sdk_managed::{Database, DatabaseConfiguration, DatabaseError},
};

// TODO: Use connection pooling with r2d2 and r2d2_sqlite?
#[derive(Clone)]
pub struct SqliteDatabase {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

fn validate_identifier(name: &'static str) -> Result<&'static str, DatabaseError> {
    if validate_registry_name(name) {
        Ok(name)
    } else {
        Err(DatabaseError::Internal(
            rusqlite::Error::InvalidParameterName(name.to_string()).to_string(),
        ))
    }
}

impl SqliteDatabase {
    async fn with_conn<R>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<R, DatabaseError>,
    ) -> Result<R, DatabaseError> {
        let guard = self.conn.lock().await;
        f(&guard)
    }

    async fn with_tx<R>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction) -> Result<R, DatabaseError>,
    ) -> Result<R, DatabaseError> {
        let mut guard = self.conn.lock().await;
        let tx = guard.transaction()?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }

    fn initialize_internal(
        mut db: rusqlite::Connection,
        migrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        // Set WAL mode for better concurrency
        db.pragma_update(None, "journal_mode", "WAL")?;

        let transaction = db.transaction()?;

        for step in &migrations.steps {
            match step {
                RepositoryMigrationStep::Add(data) => {
                    // SAFETY: SQLite tables cannot use ?, but `reg.name()` is not user controlled
                    // and is validated to only contain valid characters, so
                    // it's safe to interpolate here.
                    transaction.execute(
                        &format!(
                            "CREATE TABLE IF NOT EXISTS \"{}\" (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
                            validate_identifier(data.name())?,
                        ),
                        [],
                    )?;
                }
                RepositoryMigrationStep::Remove(data) => {
                    // SAFETY: SQLite tables cannot use ?, but `reg.name()` is not user controlled
                    // and is validated to only contain valid characters, so
                    // it's safe to interpolate here.
                    transaction.execute(
                        &format!(
                            "DROP TABLE IF EXISTS \"{}\";",
                            validate_identifier(data.name())?,
                        ),
                        [],
                    )?;
                }
            }
        }

        transaction.commit()?;
        Ok(SqliteDatabase {
            conn: Arc::new(Mutex::new(db)),
        })
    }
}

impl Database for SqliteDatabase {
    async fn initialize(
        configuration: DatabaseConfiguration,
        migrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        let DatabaseConfiguration::Sqlite {
            db_name,
            folder_path: mut path,
        } = configuration
        else {
            return Err(DatabaseError::UnsupportedConfiguration(configuration));
        };
        path.push(format!("{db_name}.sqlite"));

        let db = rusqlite::Connection::open(&path)?;
        Self::initialize_internal(db, migrations)
    }

    async fn get<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        self.with_conn(|conn| {
            // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
            // validated to only contain valid characters, so it's safe to interpolate here.
            let mut stmt = conn.prepare(&format!(
                "SELECT value FROM \"{}\" WHERE key = ?1",
                validate_identifier(T::NAME)?
            ))?;
            let mut rows = stmt.query([key])?;

            if let Some(row) = rows.next()? {
                let value = row.get::<_, String>(0)?;
                Ok(Some(serde_json::from_str(&value)?))
            } else {
                Ok(None)
            }
        })
        .await
    }

    async fn list<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<Vec<T>, DatabaseError> {
        self.with_conn(|conn| {
            // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
            // validated to only contain valid characters, so it's safe to interpolate here.
            let mut stmt = conn.prepare(&format!(
                "SELECT key, value FROM \"{}\"",
                validate_identifier(T::NAME)?
            ))?;
            let rows = stmt.query_map([], |row| row.get(1))?;

            let mut results = Vec::new();
            for row in rows {
                let value: String = row?;
                results.push(serde_json::from_str(&value)?);
            }
            Ok(results)
        })
        .await
    }

    async fn set<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
        value: T,
    ) -> Result<(), DatabaseError> {
        let value = serde_json::to_string(&value)?;
        self.with_tx(|tx| {
            // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
            // validated to only contain valid characters, so it's safe to interpolate here.
            tx.execute(
                &format!(
                    "INSERT OR REPLACE INTO \"{}\" (key, value) VALUES (?1, ?2)",
                    validate_identifier(T::NAME)?,
                ),
                [key, &value],
            )?;
            Ok(())
        })
        .await
    }

    async fn set_bulk<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        values: Vec<(String, T)>,
    ) -> Result<(), DatabaseError> {
        self.with_tx(|tx| {
            // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
            // validated to only contain valid characters, so it's safe to interpolate here.
            let sql = format!(
                "INSERT OR REPLACE INTO \"{}\" (key, value) VALUES (?1, ?2)",
                validate_identifier(T::NAME)?,
            );
            for (key, value) in values {
                let value = serde_json::to_string(&value)?;
                tx.execute(&sql, [&key, &value])?;
            }
            Ok(())
        })
        .await
    }

    async fn remove<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<(), DatabaseError> {
        self.with_tx(|tx| {
            // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
            // validated to only contain valid characters, so it's safe to interpolate here.
            tx.execute(
                &format!(
                    "DELETE FROM \"{}\" WHERE key = ?1",
                    validate_identifier(T::NAME)?
                ),
                [key],
            )?;
            Ok(())
        })
        .await
    }

    async fn remove_bulk<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        keys: Vec<String>,
    ) -> Result<(), DatabaseError> {
        self.with_tx(|tx| {
            // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
            // validated to only contain valid characters, so it's safe to interpolate here.
            let sql = format!(
                "DELETE FROM \"{}\" WHERE key = ?1",
                validate_identifier(T::NAME)?
            );
            for key in keys {
                tx.execute(&sql, [&key])?;
            }
            Ok(())
        })
        .await
    }

    async fn remove_all<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<(), DatabaseError> {
        self.with_tx(|tx| {
            // SAFETY: SQLite tables cannot use ?, but `T::NAME` is not user controlled and is
            // validated to only contain valid characters, so it's safe to interpolate here.
            tx.execute(
                &format!("DELETE FROM \"{}\"", validate_identifier(T::NAME)?),
                [],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register_repository_item;

    fn open_in_memory(steps: Vec<RepositoryMigrationStep>) -> SqliteDatabase {
        SqliteDatabase::initialize_internal(
            rusqlite::Connection::open_in_memory().unwrap(),
            RepositoryMigrations::new(steps),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_sqlite_integration() {
        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct TestA(usize);
        register_repository_item!(String => TestA, "TestItem_A");

        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct TestB(usize);
        register_repository_item!(String => TestB, "TestItem_B");

        let db = open_in_memory(vec![
            // Test that deleting a table that doesn't exist is fine
            RepositoryMigrationStep::Remove(TestB::data()),
            RepositoryMigrationStep::Add(TestA::data()),
            RepositoryMigrationStep::Add(TestB::data()),
            // Test that deleting a table that does exist is also fine
            RepositoryMigrationStep::Remove(TestB::data()),
        ]);

        assert_eq!(db.list::<TestA>().await.unwrap(), Vec::<TestA>::new());

        db.set("key1", TestA(42)).await.unwrap();
        assert_eq!(db.get::<TestA>("key1").await.unwrap(), Some(TestA(42)));

        db.remove::<TestA>("key1").await.unwrap();

        assert_eq!(db.get::<TestA>("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_sqlite_database_path_construction() {
        let temp_dir = std::env::temp_dir().join("bitwarden_state_test");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let config = DatabaseConfiguration::Sqlite {
            db_name: "test_db".to_string(),
            folder_path: temp_dir.clone(),
        };

        SqliteDatabase::initialize(config, RepositoryMigrations::new(vec![]))
            .await
            .unwrap();

        assert!(temp_dir.join("test_db.sqlite").exists());

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[tokio::test]
    async fn test_sqlite_bulk_operations() {
        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct BulkItem(u32);
        register_repository_item!(String => BulkItem, "BulkItem_sqlite");

        let db = open_in_memory(vec![RepositoryMigrationStep::Add(BulkItem::data())]);

        db.set_bulk(vec![
            ("a".to_string(), BulkItem(1)),
            ("b".to_string(), BulkItem(2)),
            ("c".to_string(), BulkItem(3)),
        ])
        .await
        .unwrap();

        let mut list = db.list::<BulkItem>().await.unwrap();
        list.sort_by_key(|item| item.0);
        assert_eq!(list, vec![BulkItem(1), BulkItem(2), BulkItem(3)]);

        db.remove_bulk::<BulkItem>(vec!["a".to_string(), "b".to_string()])
            .await
            .unwrap();
        assert_eq!(db.get::<BulkItem>("a").await.unwrap(), None);
        assert_eq!(db.get::<BulkItem>("b").await.unwrap(), None);
        assert_eq!(db.get::<BulkItem>("c").await.unwrap(), Some(BulkItem(3)));

        db.remove_all::<BulkItem>().await.unwrap();
        assert_eq!(db.list::<BulkItem>().await.unwrap(), Vec::<BulkItem>::new());
    }

    #[tokio::test]
    async fn test_sqlite_cross_type_isolation() {
        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct AlphaItem(String);
        register_repository_item!(String => AlphaItem, "AlphaItem_sqlite");

        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct BetaItem(u64);
        register_repository_item!(String => BetaItem, "BetaItem_sqlite");

        let db = open_in_memory(vec![
            RepositoryMigrationStep::Add(AlphaItem::data()),
            RepositoryMigrationStep::Add(BetaItem::data()),
        ]);

        db.set("key", AlphaItem("alpha".to_string())).await.unwrap();
        db.set("key", BetaItem(42)).await.unwrap();

        assert_eq!(
            db.get::<AlphaItem>("key").await.unwrap(),
            Some(AlphaItem("alpha".to_string()))
        );
        assert_eq!(db.get::<BetaItem>("key").await.unwrap(), Some(BetaItem(42)));

        db.remove_all::<AlphaItem>().await.unwrap();
        assert_eq!(db.get::<AlphaItem>("key").await.unwrap(), None);
        // BetaItem must be unaffected.
        assert_eq!(db.get::<BetaItem>("key").await.unwrap(), Some(BetaItem(42)));
    }

    #[tokio::test]
    async fn test_sqlite_set_overwrites_existing_key() {
        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct OverwriteItem(u32);
        register_repository_item!(String => OverwriteItem, "OverwriteItem_sqlite");

        let db = open_in_memory(vec![RepositoryMigrationStep::Add(OverwriteItem::data())]);

        db.set("k", OverwriteItem(1)).await.unwrap();
        db.set("k", OverwriteItem(2)).await.unwrap();

        assert_eq!(
            db.get::<OverwriteItem>("k").await.unwrap(),
            Some(OverwriteItem(2))
        );
        assert_eq!(db.list::<OverwriteItem>().await.unwrap().len(), 1);
    }
}
