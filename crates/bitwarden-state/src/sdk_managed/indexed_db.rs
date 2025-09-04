use js_sys::JsString;
use serde::{de::DeserializeOwned, ser::Serialize};

use crate::{
    repository::{RepositoryItem, RepositoryItemData},
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

#[derive(Clone)]
pub struct IndexedDbDatabase(
    bitwarden_threading::ThreadBoundRunner<indexed_db::Database<IndexedDbInternalError>>,
);
impl Database for IndexedDbDatabase {
    async fn initialize(
        configuration: DatabaseConfiguration,
        registrations: &[RepositoryItemData],
    ) -> Result<Self, DatabaseError> {
        let DatabaseConfiguration::IndexedDb { db_name } = configuration else {
            return Err(DatabaseError::UnsupportedConfiguration(configuration));
        };

        let factory = indexed_db::Factory::get()?;

        let registrations = registrations.to_vec();

        // TODO: This version will be replaced by a proper migration system in a followup PR:
        // https://github.com/bitwarden/sdk-internal/pull/410
        let version: u32 = 1;

        // Open the database, creating it if needed
        let db = factory
            .open(&db_name, version, async move |evt| {
                let db = evt.database();

                for reg in registrations {
                    db.build_object_store(reg.name()).create()?;
                }

                Ok(())
            })
            .await?;

        let runner = bitwarden_threading::ThreadBoundRunner::new(db);
        Ok(IndexedDbDatabase(runner))
    }

    async fn get<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        let key = key.to_string();

        let result = self
            .0
            .run_in_thread(move |db| async move {
                db.transaction(&[T::NAME])
                    .run(|t| async move {
                        let store = t.object_store(T::NAME)?;
                        let response = store.get(&JsString::from(key)).await?;

                        if let Some(value) = response {
                            Ok(::tsify::serde_wasm_bindgen::from_value(value)
                                .map_err(IndexedDbInternalError::from)?)
                        } else {
                            Ok(None)
                        }
                    })
                    .await
            })
            .await??;

        Ok(result)
    }

    async fn list<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<Vec<T>, DatabaseError> {
        let results = self
            .0
            .run_in_thread(move |db| async move {
                db.transaction(&[T::NAME])
                    .run(|t| async move {
                        let store = t.object_store(T::NAME)?;
                        let results = store.get_all(None).await?;

                        let mut items: Vec<T> = Vec::new();

                        for value in results {
                            let item: T = ::tsify::serde_wasm_bindgen::from_value(value)
                                .map_err(IndexedDbInternalError::from)?;
                            items.push(item);
                        }

                        Ok(items)
                    })
                    .await
            })
            .await??;

        Ok(results)
    }

    async fn set<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
        value: T,
    ) -> Result<(), DatabaseError> {
        let key = key.to_string();

        self.0
            .run_in_thread(move |db| async move {
                db.transaction(&[T::NAME])
                    .rw()
                    .run(|t| async move {
                        let store = t.object_store(T::NAME)?;

                        let value = ::tsify::serde_wasm_bindgen::to_value(&value)
                            .map_err(IndexedDbInternalError::from)?;

                        store.put_kv(&JsString::from(key), &value).await?;
                        Ok(())
                    })
                    .await
            })
            .await??;

        Ok(())
    }

    async fn remove<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<(), DatabaseError> {
        let key = key.to_string();

        self.0
            .run_in_thread(move |db| async move {
                db.transaction(&[T::NAME])
                    .rw()
                    .run(|t| async move {
                        let store = t.object_store(T::NAME)?;
                        store.delete(&JsString::from(key)).await?;
                        Ok(())
                    })
                    .await
            })
            .await??;

        Ok(())
    }
}
