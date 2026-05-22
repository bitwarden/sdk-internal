//! Browser-mode integration tests for the IndexedDB backend.
//!
//! Run with:
//!
//! ```text
//! cargo test --target wasm32-unknown-unknown -p bitwarden-state \
//!     --features wasm,browser-tests
//! ```
//!
//! Requires `geckodriver` or `chromedriver` on `PATH`.

#![cfg(all(target_arch = "wasm32", feature = "browser-tests"))]

use bitwarden_state::{
    DatabaseConfiguration, register_repository_item,
    registry::StateRegistry,
    repository::{RepositoryItem, RepositoryMigrationStep, RepositoryMigrations},
};
use serde::{Deserialize, Serialize};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
struct Item(String);
register_repository_item!(String => Item, "indexed_db_test_Item");

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
struct OtherItem(u32);
register_repository_item!(String => OtherItem, "indexed_db_test_OtherItem");

fn migrations(steps: Vec<RepositoryMigrationStep>) -> RepositoryMigrations {
    RepositoryMigrations::new(steps)
}

async fn registry(db_name: &str, steps: Vec<RepositoryMigrationStep>) -> StateRegistry {
    let registry = StateRegistry::new();
    registry
        .initialize_database(
            DatabaseConfiguration::IndexedDb {
                db_name: db_name.to_string(),
            },
            migrations(steps),
        )
        .await
        .expect("registry init");
    registry
}

#[wasm_bindgen_test]
async fn round_trip_set_get_list_remove() {
    let reg = registry(
        "round_trip",
        vec![RepositoryMigrationStep::Add(Item::data())],
    )
    .await;
    let repo = reg.get::<Item>().unwrap();

    assert_eq!(repo.get("k".into()).await.unwrap(), None);

    repo.set("k".into(), Item("hello".into())).await.unwrap();
    assert_eq!(
        repo.get("k".into()).await.unwrap(),
        Some(Item("hello".into()))
    );

    repo.set("k2".into(), Item("world".into())).await.unwrap();
    let mut all = repo.list().await.unwrap();
    all.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(all, vec![Item("hello".into()), Item("world".into())]);

    repo.remove("k".into()).await.unwrap();
    assert_eq!(repo.get("k".into()).await.unwrap(), None);
    assert_eq!(
        repo.get("k2".into()).await.unwrap(),
        Some(Item("world".into()))
    );

    reg.wipe().await.unwrap();
}

#[wasm_bindgen_test]
async fn bulk_operations() {
    let reg = registry("bulk", vec![RepositoryMigrationStep::Add(Item::data())]).await;
    let repo = reg.get::<Item>().unwrap();

    repo.set_bulk(vec![
        ("a".into(), Item("1".into())),
        ("b".into(), Item("2".into())),
        ("c".into(), Item("3".into())),
    ])
    .await
    .unwrap();

    let mut all = repo.list().await.unwrap();
    all.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        all,
        vec![Item("1".into()), Item("2".into()), Item("3".into())]
    );

    repo.remove_bulk(vec!["a".into(), "b".into()])
        .await
        .unwrap();
    assert_eq!(repo.get("a".into()).await.unwrap(), None);
    assert_eq!(repo.get("b".into()).await.unwrap(), None);
    assert_eq!(repo.get("c".into()).await.unwrap(), Some(Item("3".into())));

    repo.remove_all().await.unwrap();
    assert_eq!(repo.list().await.unwrap(), Vec::<Item>::new());

    reg.wipe().await.unwrap();
}

#[wasm_bindgen_test]
async fn cross_type_isolation() {
    let reg = registry(
        "cross_type",
        vec![
            RepositoryMigrationStep::Add(Item::data()),
            RepositoryMigrationStep::Add(OtherItem::data()),
        ],
    )
    .await;
    let items = reg.get::<Item>().unwrap();
    let others = reg.get::<OtherItem>().unwrap();

    items.set("k".into(), Item("alpha".into())).await.unwrap();
    others.set("k".into(), OtherItem(42)).await.unwrap();

    assert_eq!(
        items.get("k".into()).await.unwrap(),
        Some(Item("alpha".into()))
    );
    assert_eq!(others.get("k".into()).await.unwrap(), Some(OtherItem(42)));

    items.remove_all().await.unwrap();
    assert_eq!(items.get("k".into()).await.unwrap(), None);
    // OtherItem must be unaffected.
    assert_eq!(others.get("k".into()).await.unwrap(), Some(OtherItem(42)));

    reg.wipe().await.unwrap();
}

#[wasm_bindgen_test]
async fn wipe_disconnects_clones_and_deletes_database() {
    let db_name = "wipe_clones";
    let reg = registry(db_name, vec![RepositoryMigrationStep::Add(Item::data())]).await;
    let repo = reg.get::<Item>().unwrap();
    repo.set("k".into(), Item("persisted".into()))
        .await
        .unwrap();

    reg.wipe().await.unwrap();

    // Outstanding handle now errors.
    assert!(repo.get("k".into()).await.is_err());

    // Reopening the same db_name yields a fresh database — proves Factory::delete_database
    // actually removed it, not just closed the connection.
    let reg2 = registry(db_name, vec![RepositoryMigrationStep::Add(Item::data())]).await;
    let repo2 = reg2.get::<Item>().unwrap();
    assert_eq!(repo2.get("k".into()).await.unwrap(), None);

    reg2.wipe().await.unwrap();
}
