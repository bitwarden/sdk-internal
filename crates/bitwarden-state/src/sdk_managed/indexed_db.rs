use std::convert::Infallible;

use js_sys::JsString;

use crate::{
    repository::RepositoryItemData,
    sdk_managed::{Database, DatabaseError},
};

#[derive(Clone)]
pub struct IndexedDbDatabase(
    bitwarden_threading::ThreadBoundRunner<indexed_db::Database<Infallible>>,
);
impl Database for IndexedDbDatabase {
    async fn initialize(registrations: &[RepositoryItemData]) -> Result<Self, DatabaseError> {
        let factory = indexed_db::Factory::<Infallible>::get()?;

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

    async fn get(&self, namespace: &str, key: &str) -> Result<Option<String>, DatabaseError> {
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
                            Ok(value.as_string())
                        } else {
                            Ok(None)
                        }
                    })
                    .await
            })
            .await??;

        Ok(result)
    }

    async fn list(&self, namespace: &str) -> Result<Vec<String>, DatabaseError> {
        let namespace = namespace.to_string();

        let results = self
            .0
            .run_in_thread(move |db| async move {
                db.transaction(&[&namespace])
                    .run(|t| async move {
                        let store = t.object_store(&namespace)?;
                        let results = store.get_all(None).await?;

                        let items: Vec<String> = results
                            .into_iter()
                            .filter_map(|item| item.as_string())
                            .collect();

                        Ok(items)
                    })
                    .await
            })
            .await??;

        Ok(results)
    }

    async fn set(&self, namespace: &str, key: &str, value: String) -> Result<(), DatabaseError> {
        let namespace = namespace.to_string();
        let key = key.to_string();
        let value = value.to_string();

        self.0
            .run_in_thread(move |db| async move {
                db.transaction(&[&namespace])
                    .rw()
                    .run(|t| async move {
                        let store = t.object_store(&namespace)?;
                        store
                            .put_kv(&JsString::from(key), &JsString::from(value))
                            .await?;
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
