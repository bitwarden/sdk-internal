//! This example demonstrates how to securely protect keys with a password using the
//! [PasswordProtectedKeyEnvelope].

use bitwarden_crypto::{
    KeyStore, KeyStoreContext, key_ids,
    safe::{PasswordProtectedKeyEnvelope, PasswordProtectedKeyEnvelopeError},
};

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let mut disk = MockDisk::new();

    // Alice wants to protect a key with a password.
    // For example to:
    // - Protect her vault with a pin
    // - Protect her exported vault with a password
    // - Protect a send with a URL fragment secret
    // For this, the `PasswordProtectedKeyEnvelope` is used.

    // Alice has a vault protected with a symmetric key. She wants the symmetric key protected with
    // a PIN.
    let vault_key = ctx
        .generate_symmetric_key(ExampleSymmetricKey::VaultKey)
        .expect("Generating vault key should work");

    // Seal the key with the PIN
    // The KDF settings are chosen for you, and do not need to be separately tracked or synced
    // Next, store this protected key envelope on disk.
    let pin = "1234";
    let envelope =
        PasswordProtectedKeyEnvelope::seal(vault_key, pin, &ctx).expect("Sealing should work");
    disk.save("vault_key_envelope", (&envelope).into());

    // Wipe the context to simulate new session
    ctx.clear_local();

    // Load the envelope from disk and unseal it with the PIN, and store it in the context.
    let deserialized: PasswordProtectedKeyEnvelope<ExampleIds> =
        PasswordProtectedKeyEnvelope::try_from(
            disk.load("vault_key_envelope")
                .expect("Loading from disk should work"),
        )
        .expect("Deserializing envelope should work");
    deserialized
        .unseal(ExampleSymmetricKey::VaultKey, pin, &mut ctx)
        .expect("Unsealing should work");

    // Alice wants to change her password; also her KDF settings are below the minimums.
    // Re-sealing will update the password, and KDF settings.
    let envelope = envelope
        .reseal(pin, "0000")
        .expect("The password should be valid");
    disk.save("vault_key_envelope", (&envelope).into());

    // Alice wants to change the protected key. This requires creating a new envelope
    ctx.generate_symmetric_key(ExampleSymmetricKey::VaultKey)
        .expect("Generating vault key should work");
    let envelope = PasswordProtectedKeyEnvelope::seal(ExampleSymmetricKey::VaultKey, "0000", &ctx)
        .expect("Sealing should work");
    disk.save("vault_key_envelope", (&envelope).into());

    // Alice tries the password but it is wrong
    assert!(matches!(
        envelope.unseal(ExampleSymmetricKey::VaultKey, "9999", &mut ctx),
        Err(PasswordProtectedKeyEnvelopeError::WrongPassword)
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
        VaultKey
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
