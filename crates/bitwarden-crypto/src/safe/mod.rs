mod data_envelope;
mod password_protected_key_envelope;
mod wrapped_key;

#[cfg(test)]
mod tests {
    use crate::{
        safe::{
            data_envelope::{DataEnvelope, SealableData},
            password_protected_key_envelope::PasswordProtectedKeyEnvelope,
            wrapped_key::WrappedSymmetricKey,
        },
        traits::tests::{TestIds, TestSymmKey},
        KeyStore,
    };

    // These are some examples of how the safe interfaces can be used to implement various features.
    //
    // As a note for DataEnvelope; The inner struct *may* need versioning, but that is up to the consumer, if they do want to provide versioning, and omitted from examples.
    //
    // For attachments, the entry is currently two keys, encrypted by the domain object (send/cipher)'s key. Maybe the attachment should have it's own attachment key wrapping the two keys it uses.

    #[test]
    fn example_vault_export() {
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context();

        // Export data structure
        #[derive(serde::Serialize, serde::Deserialize)]
        struct VaultExport {
            username: String,
            password: String,
        }
        impl SealableData for VaultExport {}

        // Encrypt the export data
        let export = VaultExport {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };
        let data_envelope = DataEnvelope::seal(&export, TestSymmKey::A(1), &mut ctx);
        let key_envelope = PasswordProtectedKeyEnvelope::seal(TestSymmKey::A(1), "abc", &mut ctx);

        // export = {
        //     data_envelope: data_envelope,
        //     key_envelope: key_envelope,
        // }

        // Decrypt the data
        key_envelope.unseal(TestSymmKey::A(1), "abc", &mut ctx);
        let sealed_data: VaultExport = data_envelope.unseal(TestSymmKey::A(1), &mut ctx).unwrap();
    }

    #[test]
    fn example_pin_mp_bio_unlock() {
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context();

        // The key hierarchy implemented here is:
        // Pin             -> Local Device Encryption Key -> ...
        // Master Password -> ^
        // Biometrics      -> ^

        let local_device_key = TestSymmKey::A(1);
        ctx.generate_symmetric_key(local_device_key).unwrap();

        // Set up unlock methods
        let pin_key_envelope =
            PasswordProtectedKeyEnvelope::seal(local_device_key, "1234", &mut ctx);
        let master_password_key_envelope =
            PasswordProtectedKeyEnvelope::seal(local_device_key, "masterpassword", &mut ctx);

        // Biometrics
        let biometric_key = TestSymmKey::A(2);
        ctx.generate_symmetric_key(biometric_key).unwrap();
        let biometrics_wrapped_local_device_key =
            WrappedSymmetricKey::wrap(local_device_key, biometric_key, &ctx);

        // Unlocking examples
        //
        // unlock with pin
        pin_key_envelope.unseal(local_device_key, "1234", &mut ctx);
        // unlock with master password
        master_password_key_envelope.unseal(local_device_key, "masterpassword", &mut ctx);
        // unlock with biometrics
        let _unwrapped_local_device_key = biometrics_wrapped_local_device_key
            .unwrap(local_device_key, biometric_key, &mut ctx)
            .unwrap();
    }

    #[test]
    fn example_send() {
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context();

        #[derive(serde::Serialize, serde::Deserialize)]
        struct SendMetadata {
            name: String,
        }
        impl SealableData for SendMetadata {}
        #[derive(serde::Serialize, serde::Deserialize)]
        struct AttachmentBytes(Vec<u8>);
        impl SealableData for AttachmentBytes {}

        // Send data
        let url_fragment = "ABCDE"; // the URL of a send contains a fragment with the send secret. This is the password of the send.
        let metadata = SendMetadata {
            name: "Test Send".to_string(),
        };

        // Key Hierarchy:
        // Send Fragment -password-> Send Key -> Metadata Key -> Metadata
        //                                    -> Attachment1 File Data Key -> Attachment1 File Data
        //                                    -> Attachment1 Metadata Key -> Attachment Metadata [not implemented]

        // Encrypt the send
        let send_key_id = TestSymmKey::A(1);
        ctx.generate_symmetric_key(send_key_id).unwrap();

        let url_sealed_send_key =
            PasswordProtectedKeyEnvelope::seal(send_key_id, url_fragment, &mut ctx);
        let metadata_envelope = DataEnvelope::seal(&metadata, TestSymmKey::A(3), &mut ctx);

        // Encrypt attachments
        let attachment1_filedata_envelope = DataEnvelope::seal(
            &AttachmentBytes(vec![1, 2, 3, 4, 5]),
            TestSymmKey::A(3),
            &mut ctx,
        );
        let wrapped_attachment1_filedata_key =
            WrappedSymmetricKey::wrap(TestSymmKey::A(3), send_key_id, &ctx);

        // upload:
        // (
        //     url_sealed_send_key,
        //     metadata_envelope,
        //     attachments: [
        //        {
        //           key: wrapped_attachment1_filedata_key,
        //        }
        //     ]
        // ),
        // upload:
        // attachment1_filedata_envelope
    }

    #[test]
    fn example_vault_key_rotation() {
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context();

        // Ciphers:
        #[derive(serde::Serialize, serde::Deserialize)]
        struct CipherData {
            username: String,
        }
        impl SealableData for CipherData {}

        // Create vault
        // Key Hierarchy:
        // Vault Key -> Cipher Key -> Cipher Data Envelope
        //           -> Cipher Key -> Cipher Data Envelope
        //                         -> Attachment Key

        // Vault key:
        let vault_key_id = TestSymmKey::A(1);
        ctx.generate_symmetric_key(vault_key_id).unwrap();

        let mut ciphers: Vec<(DataEnvelope<TestIds>, WrappedSymmetricKey<TestIds>)> = Vec::new();
        for i in 3..10 {
            let cipher = CipherData {
                username: format!("user{}", i),
            };
            let cipher_envelope = DataEnvelope::seal(&cipher, TestSymmKey::A(i), &mut ctx);
            let wrapped_cipher_key =
                WrappedSymmetricKey::wrap(vault_key_id, TestSymmKey::A(i), &ctx);
            ciphers.push((cipher_envelope, wrapped_cipher_key));
        }
        // Upload ciphers + keys

        // Rotate the vault key
        let new_vault_key_id = TestSymmKey::A(2);
        ctx.generate_symmetric_key(new_vault_key_id).unwrap();
        // Rewrap all ciphers with the new vault key
        for (_, wrapped_cipher_key) in &ciphers {
            let new_wrapped_cipher_key = wrapped_cipher_key
                .rewrap(vault_key_id, new_vault_key_id, &mut ctx)
                .unwrap();
            // Reupload the key
            // upload: new_wrapped_cipher_key
        }
    }
}
