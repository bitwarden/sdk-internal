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
pub struct SqliteDatabase(Arc<Mutex<rusqlite::Connection>>);

fn validate_identifier(name: &'static str) -> Result<&'static str, DatabaseError> {
    if validate_registry_name(name) {
        Ok(name)
    } else {
        Err(DatabaseError::Internal(
            rusqlite::Error::InvalidParameterName(name.to_string()),
        ))
    }
}

impl SqliteDatabase {
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
        Ok(SqliteDatabase(Arc::new(Mutex::new(db))))
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
        path.set_file_name(format!("{db_name}.sqlite"));

        let db = rusqlite::Connection::open(path)?;
        Self::initialize_internal(db, migrations)
    }

    async fn get<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        let conn = self.0.lock().await;

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
    }

    async fn list<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<Vec<T>, DatabaseError> {
        let conn = self.0.lock().await;

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
                "INSERT OR REPLACE INTO \"{}\" (key, value) VALUES (?1, ?2)",
                validate_identifier(T::NAME)?,
            ),
            [key, &value],
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
            &format!(
                "DELETE FROM \"{}\" WHERE key = ?1",
                validate_identifier(T::NAME)?
            ),
            [key],
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

        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct TestB(usize);
        register_repository_item!(TestB, "TestItem_B");

        let steps = vec![
            // Test that deleting a table that doesn't exist is fine
            RepositoryMigrationStep::Remove(TestB::data()),
            RepositoryMigrationStep::Add(TestA::data()),
            RepositoryMigrationStep::Add(TestB::data()),
            // Test that deleting a table that does exist is also fine
            RepositoryMigrationStep::Remove(TestB::data()),
        ];
        let migrations = RepositoryMigrations::new(steps);

        let db = SqliteDatabase::initialize_internal(db, migrations).unwrap();

        assert_eq!(db.list::<TestA>().await.unwrap(), Vec::<TestA>::new());

        db.set("key1", TestA(42)).await.unwrap();
        assert_eq!(db.get::<TestA>("key1").await.unwrap(), Some(TestA(42)));

        db.remove::<TestA>("key1").await.unwrap();

        assert_eq!(db.get::<TestA>("key1").await.unwrap(), None);
    }
}
