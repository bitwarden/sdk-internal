//! This example demonstrates how to seal a piece of data.
//!
//! If there is a struct that should be kept secret, in can be sealed with a `DataEnvelope`. This
//! will automatically create a content-encryption-key. This is useful because the key is stored
//! separately. Rotating the encrypting key now only requires re-uploading the
//! content-encryption-key instead of the entire data. Further, server-side tampering (swapping of
//! individual fields encrypted by the same key) is prevented.
//!
//! In general, if a struct of data should be protected, the `DataEnvelope` should be used.

use bitwarden_crypto::{key_ids, safe::SealableData};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct MyItem {
    a: u64,
    b: String,
}
impl SealableData for MyItem {}

fn main() {
    let store = bitwarden_crypto::KeyStore::<ExampleIds>::default();
    let mut ctx: bitwarden_crypto::KeyStoreContext<'_, ExampleIds> = store.context_mut();
    let mut disk = MockDisk::new();

    let my_item = MyItem {
        a: 42,
        b: "Hello, World!".to_string(),
    };
    // Seal the item into an encrypted blob, and store the content-encryption-key in the context.
    let sealed_item = bitwarden_crypto::safe::DataEnvelope::seal(
        my_item,
        &bitwarden_crypto::safe::DataEnvelopeNamespace::VaultItem,
        ExampleSymmetricKey::ItemKey,
        &mut ctx,
    )
    .expect("Sealing should work");

    // Store the sealed item on disk
    disk.save("sealed_item", (&sealed_item).into());
    let sealed_item = disk
        .load("sealed_item")
        .expect("Failed to load sealed item")
        .clone();
    let sealed_item: bitwarden_crypto::safe::DataEnvelope =
        bitwarden_crypto::safe::DataEnvelope::from(sealed_item);

    let my_item: MyItem = sealed_item
        .unseal(
            &bitwarden_crypto::safe::DataEnvelopeNamespace::VaultItem,
            ExampleSymmetricKey::ItemKey,
            &mut ctx,
        )
        .expect("Unsealing should work");
    assert!(my_item.a == 42);
    assert!(my_item.b == "Hello, World!");
}

pub(crate) struct MockDisk {
    map: std::collections::HashMap<String, Vec<u8>>,
}

impl MockDisk {
    pub(crate) fn new() -> Self {
        MockDisk {
            map: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn save(&mut self, key: &str, value: Vec<u8>) {
        self.map.insert(key.to_string(), value);
    }

    pub(crate) fn load(&self, key: &str) -> Option<&Vec<u8>> {
        self.map.get(key)
    }
}

key_ids! {
    #[symmetric]
    pub enum ExampleSymmetricKey {
        #[local]
        ItemKey
    }

    #[asymmetric]
    pub enum ExampleAsymmetricKey {
        Key(u8),
    }

    #[signing]
    pub enum ExampleSigningKey {
        Key(u8),
    }
    pub ExampleIds => ExampleSymmetricKey, ExampleAsymmetricKey, ExampleSigningKey;
}
