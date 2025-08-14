use base64::{prelude::BASE64_STANDARD, Engine};
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{Decryptable, EncString, KeyStoreContext, PrimitiveEncryptable};

use crate::{migrations::registry::Migration, CipherError};

pub struct V2ToV3Migration;

impl Migration for V2ToV3Migration {
    fn source_version(&self) -> u32 {
        2
    }

    fn target_version(&self) -> u32 {
        3
    }

    fn migrate(
        &self,
        cipher_data: &mut serde_json::Value,
        ctx: Option<&mut KeyStoreContext<KeyIds>>,
        cipher_key: Option<SymmetricKeyId>,
    ) -> Result<(), CipherError> {
        let ctx =
            ctx.ok_or_else(|| CipherError::MigrationFailed("Crypto context required".to_string()))?;

        let ciphers_key = cipher_key
            .ok_or_else(|| CipherError::MigrationFailed("Cipher key required".to_string()))?;

        if let Some(fido2_credentials) = cipher_data
            .get_mut("fido2Credentials")
            .and_then(|v| v.as_array_mut())
        {
            for fido2_credential in fido2_credentials {
                if let Some(credential_id_str) = fido2_credential
                    .get("credentialId")
                    .and_then(|v| v.as_str())
                {
                    let enc_string: EncString = credential_id_str.parse()?;
                    let dec_credential_id: String = enc_string.decrypt(ctx, ciphers_key)?;
                    let b64_credential_id = BASE64_STANDARD.encode(&dec_credential_id);
                    let enc_credential_id: EncString =
                        b64_credential_id.encrypt(ctx, ciphers_key)?;

                    if let Some(obj) = fido2_credential.as_object_mut() {
                        obj.insert(
                            "credentialId".to_string(),
                            serde_json::Value::String(enc_credential_id.to_string()),
                        );
                        obj.insert(
                            "credentialIdType".to_string(),
                            serde_json::Value::String("base64".to_owned()),
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::SymmetricCryptoKey;

    use super::*;

    #[test]
    fn test_v2_to_v3_migration_fido2_credentials() {
        let key_store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        let mut ctx = key_store.context();

        let cipher_key = ctx
            .generate_symmetric_key(SymmetricKeyId::Local("test_cipher_key"))
            .unwrap();

        let original_credential_id = "test-credential-id-123";
        let encrypted_credential_id: EncString = original_credential_id
            .encrypt(&mut ctx, cipher_key)
            .unwrap();

        let mut data = serde_json::json!({
            "fido2Credentials": [
                {
                    "credentialId": encrypted_credential_id.to_string(),
                    "keyType": "public-key",
                    "rpId": "example.com"
                }
            ]
        });

        V2ToV3Migration
            .migrate(&mut data, Some(&mut ctx), Some(cipher_key))
            .unwrap();

        println!("Data {:#?}", data["fido2Credentials"]);

        let fido2_creds = data["fido2Credentials"].as_array().unwrap();
        let credential = &fido2_creds[0];

        assert_eq!(credential["credentialIdType"], "base64");

        let new_credential_id_str = credential["credentialId"].as_str().unwrap();
        let new_enc_string: EncString = new_credential_id_str.parse().unwrap();
        let decrypted_new_id: String = new_enc_string.decrypt(&mut ctx, cipher_key).unwrap();

        let expected_base64 = BASE64_STANDARD.encode(original_credential_id);
        // The decrypted value should match the expected base64 encoding
        assert_eq!(decrypted_new_id, expected_base64);

        // Verifiy other fields remain untouched
        assert_eq!(credential["keyType"], "public-key");
        assert_eq!(credential["rpId"], "example.com");
    }
}
