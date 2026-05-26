use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use indexed_db::{Error, ObjectStore};
use js_sys::JsString;
use serde::{de::DeserializeOwned, ser::Serialize};

use crate::{
    repository::{RepositoryItem, RepositoryMigrationStep, RepositoryMigrations},
    sdk_managed::{Database, DatabaseConfiguration, DatabaseError},
};

#[derive(Debug, thiserror::Error)]
#[error("IndexedDB internal error: {0}")]
pub struct IndexedDbInternalError(String);
impl From<tsify::serde_wasm_bindgen::Error> for IndexedDbInternalError {
    fn from(err: tsify::serde_wasm_bindgen::Error) -> Self {
        IndexedDbInternalError(err.to_string())
    }
}

/// [`indexed_db::Database`] doesn't close on drop, so we wrap it and implement it ourselves.
struct DatabaseHandle(indexed_db::Database<IndexedDbInternalError>);

impl Drop for DatabaseHandle {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[derive(Clone)]
pub struct IndexedDbDatabase {
    runner: Arc<Mutex<Option<bitwarden_threading::ThreadBoundRunner<DatabaseHandle>>>>,
    db_name: String,
}

impl IndexedDbDatabase {
    async fn with_store<T, R, F, Fut>(&self, write: bool, work: F) -> Result<R, DatabaseError>
    where
        T: RepositoryItem,
        R: 'static + Send + Sync,
        F: 'static + Send + Sync + FnOnce(ObjectStore<IndexedDbInternalError>) -> Fut,
        Fut: 'static + Future<Output = ::indexed_db::Result<R, IndexedDbInternalError>>,
    {
        let runner = self
            .runner
            .lock()
            .expect("Mutex is not poisoned")
            .as_ref()
            .cloned()
            .ok_or(DatabaseError::Closed)?;

        let result = runner
            .run_in_thread(move |db| async move {
                let tx = db.0.transaction(&[T::NAME]);
                let tx = if write { tx.rw() } else { tx };
                tx.run(|t| async move {
                    let store = t.object_store(T::NAME)?;
                    work(store).await
                })
                .await
            })
            .await??;
        Ok(result)
    }
}

impl Database for IndexedDbDatabase {
    async fn initialize(
        configuration: DatabaseConfiguration,
        migrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        let DatabaseConfiguration::IndexedDb { db_name } = configuration else {
            return Err(DatabaseError::UnsupportedConfiguration(configuration));
        };

        let factory = indexed_db::Factory::get()?;

        // Open the database, creating it if needed
        let db = factory
            .open(&db_name, migrations.version, async move |evt| {
                let db = evt.database();

                for step in &migrations.steps {
                    match step {
                        RepositoryMigrationStep::Add(data) => {
                            db.build_object_store(data.name()).create()?;
                        }
                        RepositoryMigrationStep::Remove(data) => {
                            match db.delete_object_store(data.name()) {
                                // If the store doesn't exist, we can ignore the error
                                Ok(_) | Err(Error::DoesNotExist) => {}
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }

                Ok(())
            })
            .await?;

        let runner = bitwarden_threading::ThreadBoundRunner::new(DatabaseHandle(db));
        Ok(IndexedDbDatabase {
            runner: Arc::new(Mutex::new(Some(runner))),
            db_name,
        })
    }

    async fn get<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        let key = key.to_string();
        self.with_store::<T, _, _, _>(false, |store| async move {
            let response = store.get(&JsString::from(key)).await?;
            if let Some(value) = response {
                Ok(::tsify::serde_wasm_bindgen::from_value(value)
                    .map_err(IndexedDbInternalError::from)?)
            } else {
                Ok(None)
            }
        })
        .await
    }

    async fn list<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<Vec<T>, DatabaseError> {
        self.with_store::<T, _, _, _>(false, |store| async move {
            let results = store.get_all(None).await?;
            let mut items: Vec<T> = Vec::with_capacity(results.len());
            for value in results {
                items.push(
                    ::tsify::serde_wasm_bindgen::from_value(value)
                        .map_err(IndexedDbInternalError::from)?,
                );
            }
            Ok(items)
        })
        .await
    }

    async fn set<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
        value: T,
    ) -> Result<(), DatabaseError> {
        let key = key.to_string();
        self.with_store::<T, _, _, _>(true, |store| async move {
            let value = ::tsify::serde_wasm_bindgen::to_value(&value)
                .map_err(IndexedDbInternalError::from)?;
            store.put_kv(&JsString::from(key), &value).await?;
            Ok(())
        })
        .await
    }

    async fn set_bulk<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        values: Vec<(String, T)>,
    ) -> Result<(), DatabaseError> {
        self.with_store::<T, _, _, _>(true, |store| async move {
            for (key, value) in values {
                let value = ::tsify::serde_wasm_bindgen::to_value(&value)
                    .map_err(IndexedDbInternalError::from)?;
                store.put_kv(&JsString::from(key), &value).await?;
            }
            Ok(())
        })
        .await
    }

    async fn remove<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<(), DatabaseError> {
        let key = key.to_string();
        self.with_store::<T, _, _, _>(true, |store| async move {
            store.delete(&JsString::from(key)).await?;
            Ok(())
        })
        .await
    }

    async fn remove_bulk<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        keys: Vec<String>,
    ) -> Result<(), DatabaseError> {
        self.with_store::<T, _, _, _>(true, |store| async move {
            for key in keys {
                store.delete(&JsString::from(key)).await?;
            }
            Ok(())
        })
        .await
    }

    async fn remove_all<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<(), DatabaseError> {
        self.with_store::<T, _, _, _>(true, |store| async move {
            store.clear().await?;
            Ok(())
        })
        .await
    }

    async fn wipe(&self) -> Result<(), DatabaseError> {
        drop(self.runner.lock().expect("Mutex is not poisoned").take());
        indexed_db::Factory::get()?
            .delete_database(&self.db_name)
            .await?;
        Ok(())
    }
}
