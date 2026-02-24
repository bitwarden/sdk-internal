//! This example demonstrates how to protect a symmetric key with another symmetric key using the
//! [`SymmetrickeyEnvelope`].

use bitwarden_crypto::{
    KeyStore, KeyStoreContext, key_ids,
    safe::{SymmetricKeyEnvelopeError, SymmetricKeyEnvelopeNamespace, SymmetrickeyEnvelope},
};

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let mut disk = MockDisk::new();

    // Alice has a vault key and wants to protect it with another key.
    // For example, this can be used to persist the vault key while keeping it encrypted at rest.
    let vault_key = ctx.generate_symmetric_key();
    let wrapping_key = ctx.generate_symmetric_key();

    // Seal the vault key with the wrapping key, then store the envelope on disk.
    let envelope = SymmetrickeyEnvelope::seal(
        vault_key,
        wrapping_key,
        // IMPORTANT: Use a unique namespace for your use-case.
        SymmetricKeyEnvelopeNamespace::SessionKey,
        &ctx,
    )
    .expect("Sealing should work");
    disk.save("vault_key_envelope", (&envelope).into());

    // Load the envelope from disk and unseal it using the wrapping key.
    let deserialized = SymmetrickeyEnvelope::try_from(
        disk.load("vault_key_envelope")
            .expect("Loading from disk should work"),
    )
    .expect("Deserializing envelope should work");

    let _unsealed_key = deserialized
        .unseal(
            wrapping_key,
            SymmetricKeyEnvelopeNamespace::SessionKey,
            &mut ctx,
        )
        .expect("Unsealing should work");

    // Unsealing with the wrong wrapping key fails.
    let wrong_wrapping_key = ctx.generate_symmetric_key();
    assert!(matches!(
        envelope.unseal(
            wrong_wrapping_key,
            SymmetricKeyEnvelopeNamespace::SessionKey,
            &mut ctx
        ),
        Err(SymmetricKeyEnvelopeError::WrongKey)
    ));
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
        VaultKey(LocalId),
    }

    #[private]
    pub enum ExamplePrivateKey {
        Key(u8),
        #[local]
        Local(LocalId)
    }

    #[signing]
    pub enum ExampleSigningKey {
        Key(u8),
        #[local]
        Local(LocalId)
    }

   pub ExampleIds => ExampleSymmetricKey, ExamplePrivateKey, ExampleSigningKey;
}
