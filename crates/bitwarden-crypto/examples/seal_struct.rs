//! This example demonstrates how to seal a piece of data.
//!
//! If there is a struct that should be kept secret, in can be sealed with a `DataEnvelope`. This
//! will automatically create a content-encryption-key. This is useful because the key is stored
//! separately. Rotating the encrypting key now only requires re-uploading the
//! content-encryption-key instead of the entire data. Further, server-side tampering (swapping of
//! individual fields encrypted by the same key) is prevented.
//!
//! In general, if a struct of data should be protected, the `DataEnvelope` should be used.

use bitwarden_crypto::{
    generate_versioned_sealable, key_ids,
    safe::{DataEnvelope, DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct MyItemV1 {
    a: u32,
    b: String,
}
impl SealableData for MyItemV1 {}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct MyItemV2 {
    a: u32,
    b: bool,
    c: bool,
}
impl SealableData for MyItemV2 {}

generate_versioned_sealable!(
    MyItem,
    DataEnvelopeNamespace::VaultItem,
    [
        MyItemV1 => "1",
        MyItemV2 => "2",
    ]
);

fn main() {
    let store: bitwarden_crypto::KeyStore<ExampleIds> =
        bitwarden_crypto::KeyStore::<ExampleIds>::default();
    let mut ctx: bitwarden_crypto::KeyStoreContext<'_, ExampleIds> = store.context_mut();
    let mut disk = MockDisk::new();

    let my_item: MyItem = MyItemV1 {
        a: 42,
        b: "Hello, World!".to_string(),
    }
    .into();

    // Seals the item into an encrypted blob, and stores the content-encryption-key in the context.
    // Returned is the sealed item, along with the id of the content-encryption-key used to seal it
    // on the context. The cek has to be protected separately. Alternatively
    // `seal_with_wrapping_key` can be used to directly obtain back the wrapped cek.
    let (sealed_item, cek) = DataEnvelope::seal(my_item, &mut ctx).expect("Sealing should work");

    // Store the sealed item on disk
    disk.save("sealed_item", (&sealed_item).into());
    let sealed_item = disk
        .load("sealed_item")
        .expect("Failed to load sealed item")
        .clone();
    let sealed_item = DataEnvelope::from(sealed_item);

    // Unseal the item again, using the content-encryption-key stored in the context.
    let my_item: MyItem = sealed_item
        .unseal(cek, &mut ctx)
        .expect("Unsealing should work");
    assert!(matches!(my_item, MyItem::MyItemV1(item) if item.a == 42 && item.b == "Hello, World!"));
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
        ItemKey(LocalId)
    }

    #[asymmetric]
    pub enum ExampleAsymmetricKey {
        Key(u8),
        #[local]
        Local(LocalId),
    }

    #[signing]
    pub enum ExampleSigningKey {
        Key(u8),
        #[local]
        Local(LocalId),
    }
    pub ExampleIds => ExampleSymmetricKey, ExampleAsymmetricKey, ExampleSigningKey;
}
