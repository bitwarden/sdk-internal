#![allow(clippy::print_stdout)]
//! This example demonstrates the streaming attachment cipher end-to-end against a
//! real file on disk: stream plaintext through [`StreamingAttachmentEncryptor`] into
//! `tokio::fs::File`, then stream the resulting wire bytes back through
//! [`StreamingAttachmentDecryptor`] reading from the same file. AES-256-CBC +
//! HMAC-SHA256 is used because it is the attachment format reachable through the
//! crate's currently re-exported public API.

use std::env::temp_dir;

use bitwarden_crypto::{
    StreamingAttachmentDecryptor, StreamingAttachmentEncryptor, SymmetricCryptoKey,
    SymmetricKeyAlgorithm,
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
    //
    // AES-CBC-HMAC has to buffer the full plaintext to compute the trailing HMAC, so the
    // wire payload (0x02 || IV || MAC || ciphertext) is only written to the file during
    // `.shutdown()`.
    {
        let file = File::create(&path)
            .await
            .expect("create attachment ciphertext file");
        let mut enc = StreamingAttachmentEncryptor::new(key.clone(), None)
            .expect("AES-CBC-HMAC key is a supported variant");
        enc.write_all(&plaintext).await.expect("write_all");
        enc.shutdown().await.expect("shutdown");
    }

    let wire_len = tokio::fs::metadata(&path)
        .await
        .expect("stat ciphertext file")
        .len();
    println!(
        "Wrote {} bytes of plaintext as {} bytes of wire to {} \
         (discriminator + IV + MAC + ciphertext).",
        plaintext.len(),
        wire_len,
        path.display(),
    );

    // Decrypt: stream the wire bytes back from the file through the decryptor.
    let roundtripped = {
        let file = File::open(&path).await.expect("open ciphertext file");
        let mut dec = StreamingAttachmentDecryptor::new(key, file)
            .expect("AES-CBC-HMAC key is a supported variant");
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.expect("read_to_end");
        out
    };

    assert_eq!(roundtripped, plaintext, "plaintext must roundtrip exactly");
    println!(
        "Roundtrip succeeded — recovered {} bytes of plaintext.",
        roundtripped.len(),
    );

    tokio::fs::remove_file(&path)
        .await
        .expect("remove ciphertext file");
}
