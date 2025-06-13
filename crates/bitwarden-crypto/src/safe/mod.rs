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
        let data_envelope = DataEnvelope::seal(&export, &mut ctx, TestSymmKey::A(1));
        let key_envelope = PasswordProtectedKeyEnvelope::seal("abc", &mut ctx, TestSymmKey::A(1));

        // export = {
        //     data_envelope: data_envelope,
        //     key_envelope: key_envelope,
        // }

        key_envelope.unseal("abc", &mut ctx, TestSymmKey::A(1));
        let sealed_data: VaultExport = data_envelope.unseal(&mut ctx, TestSymmKey::A(1));
        assert_eq!(sealed_data.username, "testuser");
        assert_eq!(sealed_data.password, "testpass");
    }

    #[test]
    fn example_pin_mp_bio_unlock() {
        let store: KeyStore<TestIds> = KeyStore::default();
        let mut ctx = store.context();

        // The key hierarchy implemented here is:
        // Pin             -> Local Device Encryption Key -> ...
        // Master Password -> ^

        let local_device_key = TestSymmKey::A(1);
        ctx.generate_symmetric_key(local_device_key).unwrap();

        // Set up unlock methods
        let pin_key_envelope =
            PasswordProtectedKeyEnvelope::seal("1234", &mut ctx, local_device_key);
        let master_password_key_envelope =
            PasswordProtectedKeyEnvelope::seal("masterpassword", &mut ctx, local_device_key);

        // Biometrics
        let biometric_key = TestSymmKey::A(2);
        ctx.generate_symmetric_key(biometric_key).unwrap();
        let biometrics_wrapped_local_device_key =
            WrappedSymmetricKey::wrap(&ctx, biometric_key, local_device_key);

        // Unlocking examples
        //
        // unlock with pin
        pin_key_envelope.unseal("1234", &mut ctx, local_device_key);
        // unlock with master password
        master_password_key_envelope.unseal("masterpassword", &mut ctx, local_device_key);
        // unlock with biometrics
        let _unwrapped_local_device_key = biometrics_wrapped_local_device_key
            .unwrap(&ctx, biometric_key)
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

        let send_key_id = TestSymmKey::A(1);
        ctx.generate_symmetric_key(send_key_id).unwrap();

        let url_fragment = "ABCDE"; // the URL of a send contains a fragment with the send secret. This is the password of the send.
        let url_sealed_send_key =
            PasswordProtectedKeyEnvelope::seal(url_fragment, &mut ctx, send_key_id);

        let metadata = SendMetadata {
            name: "Test Send".to_string(),
        };
        let metadata_envelope = DataEnvelope::seal(&metadata, &mut ctx, send_key_id);

        #[derive(serde::Serialize, serde::Deserialize)]
        struct AttachmentBytes(Vec<u8>);
        impl SealableData for AttachmentBytes {}

        let attachment_key_id = TestSymmKey::A(2);
        let attachment1 = AttachmentBytes(vec![1, 2, 3, 4, 5]);
        let attachment1_envelope = DataEnvelope::seal(&attachment1, &mut ctx, attachment_key_id);
        let attachment1_wrapped_key =
            WrappedSymmetricKey::wrap(&ctx, send_key_id, attachment_key_id);

        // upload:
        // (
        //     url_sealed_send_key,
        //     metadata_envelope,
        //     attachments: [
        //        {
        //           attachment_key: attachment1_wrapped_key,
        //        }
        //     ]
        // ),
        // upload:
        // attachment1_envelope
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

        // Vault key:
        let vault_key_id = TestSymmKey::A(1);
        ctx.generate_symmetric_key(vault_key_id).unwrap();

        let mut ciphers: Vec<(DataEnvelope<TestIds>, WrappedSymmetricKey<TestIds>)> = Vec::new();
        for i in 3..10 {
            let cipher = CipherData {
                username: format!("user{}", i),
            };
            let cipher_envelope = DataEnvelope::seal(&cipher, &mut ctx, TestSymmKey::A(i));
            let wrapped_cipher_key =
                WrappedSymmetricKey::wrap(&ctx, vault_key_id, TestSymmKey::A(i));
            ciphers.push((cipher_envelope, wrapped_cipher_key));
        }
        // Upload ciphers + keys

        // Rotate the vault key
        let new_vault_key_id = TestSymmKey::A(2);
        ctx.generate_symmetric_key(new_vault_key_id).unwrap();
        // Rewrap all ciphers with the new vault key
        for (_, wrapped_cipher_key) in &ciphers {
            let new_wrapped_cipher_key = wrapped_cipher_key
                .rewrap(&ctx, vault_key_id, new_vault_key_id)
                .unwrap();
            // Reupload the key
            // upload: new_wrapped_cipher_key
        }
    }
}
