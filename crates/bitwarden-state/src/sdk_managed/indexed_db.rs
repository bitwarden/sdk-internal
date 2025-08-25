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
        let DatabaseConfiguration::IndexedDb { db_name: _db_name } = configuration else {
            return Err(DatabaseError::UnsupportedConfiguration(configuration));
        };

        let factory = indexed_db::Factory::get()?;

        let registrations = registrations.to_vec();

        // Sum all the versions of the registrations to determine the database version
        // TODO: We should do a better versioning strategy, as this won't work if one repository is
        // removed
        let version: u32 = registrations.iter().map(|reg| reg.version).sum();

        // Open the database, creating it if needed
        let db = factory
            .open("bitwarden-sdk-test-db", version, async move |evt| {
                let db = evt.database();

                for reg in registrations {
                    db.build_object_store(reg.name).create()?;
                }

                Ok(())
            })
            .await?;

        let runner = bitwarden_threading::ThreadBoundRunner::new(db);
        Ok(IndexedDbDatabase(runner))
    }

    async fn get<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        let namespace = namespace.to_string();
        let key = key.to_string();

        let result = self
            .0
            .run_in_thread(move |db| async move {
                db.transaction(&[&namespace])
                    .run(|t| async move {
                        let store = t.object_store(&namespace)?;
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
        namespace: &str,
    ) -> Result<Vec<T>, DatabaseError> {
        let namespace = namespace.to_string();

        let results = self
            .0
            .run_in_thread(move |db| async move {
                db.transaction(&[&namespace])
                    .run(|t| async move {
                        let store = t.object_store(&namespace)?;
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
        namespace: &str,
        key: &str,
        value: T,
    ) -> Result<(), DatabaseError> {
        let namespace = namespace.to_string();
        let key = key.to_string();

        self.0
            .run_in_thread(move |db| async move {
                db.transaction(&[&namespace])
                    .rw()
                    .run(|t| async move {
                        let store = t.object_store(&namespace)?;

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

    async fn remove(&self, namespace: &str, key: &str) -> Result<(), DatabaseError> {
        let namespace = namespace.to_string();
        let key = key.to_string();

        self.0
            .run_in_thread(move |db| async move {
                db.transaction(&[&namespace])
                    .rw()
                    .run(|t| async move {
                        let store = t.object_store(&namespace)?;
                        store.delete(&JsString::from(key)).await?;
                        Ok(())
                    })
                    .await
            })
            .await??;

        Ok(())
    }
}
