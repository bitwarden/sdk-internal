//! This example demonstrates how to securely protect keys with a high-entropy secret using the
//! [SecretProtectedKeyEnvelope].
//!
//! Unlike the [bitwarden_crypto::safe::PasswordProtectedKeyEnvelope], which is meant for
//! low-entropy secrets (PIN, password) and uses a slow, memory-hard KDF, this envelope is meant for
//! high-entropy secrets of arbitrary length (a random URL-fragment secret, a derived key, random
//! bytes) and uses a cheap KDF.

use bitwarden_crypto::{
    KeyStore, KeyStoreContext, key_slot_ids,
    safe::{
        ContentEncryptionKey, HighEntropySecret, SecretProtectedKeyEnvelope,
        SecretProtectedKeyEnvelopeError, SecretProtectedKeyEnvelopeNamespace,
    },
};

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let mut disk = MockDisk::new();

    // Alice wants to protect a key with a high-entropy secret.
    // For example to:
    // - Protect a send with a random URL fragment secret
    //   - Here, The secret key envelope wraps a KEK, the KEK wraps a CEK, and the CEK wraps the
    //     data.
    // - Protect a key with a (derived) secret, external to the SDK
    //   - Here, the secret key envelope wraps a the key
    // For this, the `SecretProtectedKeyEnvelope` is used.
    // (For low-entropy secrets such as a PIN, use the `PasswordProtectedKeyEnvelope` instead.)

    // Alice has some data protected with a symmetric key. She wants the symmetric key protected
    // with a high-entropy secret (here, 16 random bytes).
    let data_key = ContentEncryptionKey::make(&mut ctx);
    let secret = HighEntropySecret::make(16).expect("16 bytes is a valid size");

    // Seal the key with the secret.
    // The KDF salt is chosen for you, and does not need to be separately tracked or synced.
    // Next, store this protected key envelope on disk.
    let envelope = SecretProtectedKeyEnvelope::seal(
        data_key,
        &secret,
        // The namespace must be replaced with an appropriate namespace for the use-case
        SecretProtectedKeyEnvelopeNamespace::OrganizationInvite,
        &ctx,
    )
    .expect("Sealing should work");
    disk.save("data_key_envelope", (&envelope).into());

    // Wipe the context to simulate new session
    ctx.clear_local();

    // Load the envelope from disk and unseal it with the secret, and store it in the context.
    let deserialized: SecretProtectedKeyEnvelope = SecretProtectedKeyEnvelope::try_from(
        disk.load("data_key_envelope")
            .expect("Loading from disk should work"),
    )
    .expect("Deserializing envelope should work");
    let _unsealed_data_key = deserialized
        .unseal(
            &secret,
            // The namespace must be replaced with an appropriate namespace for the use-case
            SecretProtectedKeyEnvelopeNamespace::OrganizationInvite,
            &mut ctx,
        )
        .expect("Unsealing should work");

    // Alice wants to rotate the secret. Re-sealing will update the secret and salt.
    let new_secret = HighEntropySecret::make(16).expect("16 bytes is a valid size");
    let envelope = envelope
        .reseal(
            &secret,
            &new_secret,
            // The namespace must be replaced with an appropriate namespace for the use-case
            SecretProtectedKeyEnvelopeNamespace::OrganizationInvite,
        )
        .expect("The secret should be valid");
    disk.save("data_key_envelope", (&envelope).into());

    // Alice wants to change the protected key. This requires creating a new envelope
    let data_key = ContentEncryptionKey::make(&mut ctx);
    let envelope = SecretProtectedKeyEnvelope::seal(
        data_key,
        &new_secret,
        // The namespace must be replaced with an appropriate namespace for the use-case
        SecretProtectedKeyEnvelopeNamespace::OrganizationInvite,
        &ctx,
    )
    .expect("Sealing should work");
    disk.save("data_key_envelope", (&envelope).into());

    // Alice tries a secret but it is wrong
    let wrong_secret = HighEntropySecret::make(16).expect("16 bytes is a valid size");
    assert!(matches!(
        envelope.unseal(
            &wrong_secret,
            // The namespace must be replaced with an appropriate namespace for the use-case
            SecretProtectedKeyEnvelopeNamespace::OrganizationInvite,
            &mut ctx
        ),
        Err(SecretProtectedKeyEnvelopeError::WrongSecret)
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

key_slot_ids! {
    #[symmetric]
    pub enum ExampleSymmetricKey {
        #[local]
        DataKey(LocalId)
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
