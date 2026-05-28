//! This example demonstrates the streaming attachment cipher end-to-end against a
//! real file on disk: stream plaintext through [`StreamingAttachmentEncryptor`] into
//! `tokio::fs::File`, then stream the resulting wire bytes back through
//! [`StreamingAttachmentDecryptor`] reading from the same file.

use std::env::temp_dir;

use bitwarden_crypto::{
    KeyStore, StreamingAttachmentDecryptor, StreamingAttachmentEncryptor, SymmetricCryptoKey,
    SymmetricKeyAlgorithm, key_slot_ids,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let plaintext: Vec<u8> = (0..256_000).map(|i| (i % 251) as u8).collect();

    let path = temp_dir().join("bitwarden-streaming-attachment-example.bin");

    // Encrypt: pipe plaintext through the encryptor into a file on disk.
    {
        let file = File::create(&path)
            .await
            .expect("create attachment ciphertext file");
        let mut enc = {
            let key_store: KeyStore<ExampleIds> = KeyStore::default();
            let mut ctx = key_store.context_mut();
            let key_slot = ctx.add_local_symmetric_key(key.clone());
            StreamingAttachmentEncryptor::new(key_slot, ctx, file)
                .expect("AES-CBC-HMAC key is a supported variant")
        };
        enc.write_all(&plaintext).await.expect("write_all");
        enc.shutdown().await.expect("shutdown");
    }

    // Decrypt: stream the wire bytes back from the file through the decryptor.
    let roundtripped = {
        let file = File::open(&path).await.expect("open ciphertext file");
        let mut dec = {
            let key_store: KeyStore<ExampleIds> = KeyStore::default();
            let mut ctx = key_store.context_mut();
            let key_slot = ctx.add_local_symmetric_key(key.clone());
            StreamingAttachmentDecryptor::new(key_slot, ctx, file)
                .expect("AES-CBC-HMAC key is a supported variant")
        };
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.expect("read_to_end");
        out
    };

    assert_eq!(roundtripped, plaintext, "plaintext must roundtrip exactly");
    tokio::fs::remove_file(&path)
        .await
        .expect("remove ciphertext file");
}

key_slot_ids! {
    #[symmetric]
    pub enum ExampleSymmetricKey {
        #[local]
        ItemKey(LocalId)
    }

    #[private]
    pub enum ExamplePrivateKey {
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
    pub ExampleIds => ExampleSymmetricKey, ExamplePrivateKey, ExampleSigningKey;
}
