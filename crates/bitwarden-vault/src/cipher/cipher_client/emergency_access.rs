use bitwarden_core::key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId};
use bitwarden_crypto::{Decryptable, KeyStore, KeyStoreContext, UnsignedSharedKey};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    Cipher, CipherView, CiphersClient, DecryptCipherResult, DecryptError,
    cipher::cipher::StrictDecrypt,
};

/// Decrypts a grantor's ciphers shared with the current user through emergency access.
///
/// The grantor's user key arrives encapsulated to the grantee's public key. It is decapsulated
/// into a local key slot and used in place of each cipher's natural `User`/`Organization` slot,
/// so it never leaves the key store.
pub(super) fn decrypt_emergency_access_list(
    grantor_key: UnsignedSharedKey,
    ciphers: Vec<Cipher>,
    key_store: &KeyStore<KeySlotIds>,
    use_strict_decryption: bool,
) -> Result<DecryptCipherResult, DecryptError> {
    let mut ctx = key_store.context();
    let grantor_key_id = grantor_key.decapsulate(PrivateKeySlotId::UserPrivateKey, &mut ctx)?;

    // Keep one context for the whole list; clearing local keys would drop the grantor key.
    let mut successes = Vec::with_capacity(ciphers.len());
    let mut failures = Vec::new();
    for cipher in ciphers {
        match decrypt_one(&cipher, &mut ctx, grantor_key_id, use_strict_decryption) {
            Ok(view) => successes.push(view),
            Err(_) => failures.push(cipher),
        }
    }

    Ok(DecryptCipherResult {
        successes,
        failures,
    })
}

fn decrypt_one(
    cipher: &Cipher,
    ctx: &mut KeyStoreContext<KeySlotIds>,
    key: SymmetricKeySlotId,
    use_strict_decryption: bool,
) -> Result<CipherView, bitwarden_crypto::CryptoError> {
    if use_strict_decryption {
        return StrictDecrypt(cipher.clone()).decrypt(ctx, key);
    }

    cipher.decrypt(ctx, key)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Decrypts a grantor's ciphers returned by the emergency access view endpoint.
    ///
    /// `grantor_key` is the grantor's user key encapsulated to the current user's public key
    /// (`keyEncrypted` in the view response). Ciphers that fail to decrypt are returned in
    /// `failures`.
    pub async fn decrypt_emergency_access_list(
        &self,
        grantor_key: UnsignedSharedKey,
        ciphers: Vec<Cipher>,
    ) -> Result<DecryptCipherResult, DecryptError> {
        decrypt_emergency_access_list(
            grantor_key,
            ciphers,
            &self.key_store,
            self.is_strict_decrypt().await,
        )
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{Client, client::test_accounts::test_bitwarden_com_account_v2};

    use super::*;
    use crate::{VaultClientExt, cipher::blob::try_parse_blob};

    // Recorded with the grantor `test_bitwarden_com_account` and the grantee
    // `test_bitwarden_com_account_v2`. Never regenerate these to make a test pass: a vector that
    // stops decrypting is a backward-compatibility break.

    /// Grantor user key encapsulated to the grantee's public key, as the server returns it.
    const TEST_VECTOR_GRANTOR_KEY: &str = "4.bbiAjKYUjktIP1PggRJ+ha+O8M0LxWCNkv2bir5QHIYQnAwtx9X3Cta4j0JFnDS2Zy/UFAzRMCpdLR1DgupZ31lZvAhThC86hDvMMa0h84d7o41Rx9tCvqW1FcziuAA0UEr+Gfkc0+qX5yPFEn2eJ2U+ft9J7rSTTDeha1QIMhYnTf2sD2O0nSWSSPoFNLLg2WKoe9uXC5w+MemcK6x6ogG2T77fDr5trXnK7SoWamAWjhK65bYxYrSIpJOtdCR0O9ZIqiITg0lS0I6ACbiFBpHyo+wb+ZUCieUWrNaBjNHHES2XqEWSVVgz1XL2Q0Vh9XNwwPZLbIWZDxbz8FWqeQ==";
    /// Grantor user key encapsulated to the grantor's own public key.
    const TEST_VECTOR_WRONG_GRANTOR_KEY: &str = "4.PBhgsvKoOu8weZWhRAjPoSrucZneEh0Nc+R3xATSuJQk0GyS+xAagJX3Kh7EuPM2pU2OjGbGJeutDpNbp1EKWyYnPzbgXkMi8VU7dnbT8FmidRr/BcrNdcaNzyzJ06GPnL+wPH047iEhzP6DK7prjd3ufEtRp+x9ZCHPnN/vqzoWJD8AZfbC1c8jQFJSaTV/DfkKrF5rfTH3qoQYUNdfL5HOsbTHM8HTMsR18qtj4w638le1ejsjFFgAihcCdlLRsu6okGWCV6LZK3LyjfzXr/WliJUPV3/lySCHEyZoefK52v3TJ8Xy22Tqo+Y86IA/N/UA58c6tV/Iu1Gv3KQsPA==";
    /// Login "legacy" (password "pass"), legacy field-level encryption under the grantor user key.
    const TEST_VECTOR_LEGACY_CIPHER: &str = r#"{"id":null,"organizationId":null,"folderId":null,"collectionIds":[],"key":null,"name":"2.464q0KbAxs3hIhCJ6O/Xxw==|Kwcifl1PAd2KsD4o6nlFdQ==|HrJmneai/21EDb9OmTTQct6b3/nn3ivCIU5SqW0/in4=","notes":null,"type":1,"login":{"username":"2.8e+rqQTBrICEiROAaFShsg==|LlnpGmz/4Vz+/qvVvKeFHA==|1a5pAef2hhJfNFhj45Nok8Boq+wfLC70s3ss/Bbze0s=","password":"2.SPnq6YStUb41/JwNrW8gtA==|12wZdM4ieSJJZnBHo3KWlg==|WIleZuG8RdHQNV3DCWWUL3phwDU83W+7igU2E2LYSJA=","passwordRevisionDate":null,"uris":null,"totp":null,"autofillOnPageLoad":null,"fido2Credentials":null},"identity":null,"card":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"favorite":false,"reprompt":0,"organizationUseTotp":false,"edit":true,"permissions":null,"viewPassword":true,"localData":null,"attachments":null,"fields":null,"passwordHistory":null,"creationDate":"2024-01-01T00:00:00Z","deletedDate":null,"revisionDate":"2024-01-01T00:00:00Z","archivedDate":null,"data":null}"#;
    /// Login "blob" (password "pass"), blob encryption under the grantor user key.
    const TEST_VECTOR_BLOB_CIPHER: &str = r#"{"id":null,"organizationId":null,"folderId":null,"collectionIds":[],"key":"2.Mup/pT+Qs7w8ypIQHNDPeg==|MwjPTr4GrhCD1QA5fntk3XzCduTHKeY8YFEpDceoolLboLE+7rb8rTGWqf2QJVAUxqgtCejT6J1w55YormzjYEP1pTbP1onXYNTnyeyjk1s=|W35zL1xvXDRD9YB0QFV98lAi/qAp+MvAgII1upUrujc=","name":null,"notes":null,"type":1,"login":null,"identity":null,"card":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"favorite":false,"reprompt":0,"organizationUseTotp":false,"edit":true,"permissions":null,"viewPassword":true,"localData":null,"attachments":null,"fields":null,"passwordHistory":null,"creationDate":"2024-01-01T00:00:00Z","deletedDate":null,"revisionDate":"2024-01-01T00:00:00Z","archivedDate":null,"data":"{\"format_version\":1,\"wrapped_cek\":\"2.tI8VAPnduRNp5mqrhGAozQ==|NYgnD7bpK8lRRKm8Xp66YSdpETrLDYZhfDDLTCCmm+NReNPwUEH+PNCWiDmupXA25MHipVR+taGO5+fQgDUDMB+wYZhki3QWvigxV+EO9LA=|UdjlfQgWLtkdHEykgWl05c2Km0OJDaXq56LRSveiRp0=\",\"envelope\":\"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUNb+5HvtZQFf1MDlluqcjhk6AAE4gQI6AAE4gAGhBUzcWa1lfmjYjNurpWhYl8LLSI7A4ZZjiUj92GFVFiH4CyzpSWdrEpmYv9e7MKsupI+nJJbO8BrPGkSepord8QKA0TNDbkPtVNpwgqkSDlKJ0Kx2nLGMA4S/RdfouKJZRpyv6hUV4gMRUF2zC8DWUhIQTBXm81l6b2aMGe0zLe9Jd4ZTxNREt0PIot8+dE4559EPpfN/DPl7VeXZNHKJzGIW56fXYac=\"}"}"#;
    /// Login "other", blob encryption under a key unrelated to the grantor.
    const TEST_VECTOR_OTHER_KEY_CIPHER: &str = r#"{"id":null,"organizationId":null,"folderId":null,"collectionIds":[],"key":"2.hpRJrOTB+2Nmiy5CgVujjA==|XwGLovy+DP7oVIUw6uS/FO3tKjVxloggdd3SS/hyXkl4jOTz4wj+sKtNRfQBClZ0gxhA9xB2G4H3k/FSVr3ZKN8I31AQvJaFmYJb/QnKRok=|xAJygGDtWjsDDEwEIsBQOqk8dsfWmdpFvJchbA+CXLs=","name":null,"notes":null,"type":1,"login":null,"identity":null,"card":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"favorite":false,"reprompt":0,"organizationUseTotp":false,"edit":true,"permissions":null,"viewPassword":true,"localData":null,"attachments":null,"fields":null,"passwordHistory":null,"creationDate":"2024-01-01T00:00:00Z","deletedDate":null,"revisionDate":"2024-01-01T00:00:00Z","archivedDate":null,"data":"{\"format_version\":1,\"wrapped_cek\":\"2.5blC2aAA8CSG9+0TGwM8kQ==|N8agG47rDOKXfad8IRXiBYn4sdSqIRblOBG3cTmF4MNatMWMyNQ1eiBI3ESwXFGckSWXDWDiIYjcA5PtSTuZD3TMHbEViA35ETPyZ3p7TQk=|+JAq5PcDmGn33DroTbFHNVk2foKW0zD+0ciiZgK2R+4=\",\"envelope\":\"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUH+IGveCBNLVKkWxFC6Cj8A6AAE4gQI6AAE4gAGhBUwhbDAGkN2AhbXVNQtYmOEmXbdcL1B2nsuoI906sAHORuyQu19HsuQzu/bZiOyuHGR/f5Vi0EOhVa0+AhHZoUGI29BE+PgJOnVjuHk25z8j7XHqiw4qt+CKcbJRR6o2RC5QUgEvFl1M9+3P9wuVkijs7hu8CaCjcyyGGA3KnN3vJ5EXP4oqtteamB1jyHx9PxXV2ZuCQVDsFb6bMoO/bnBhTSuLe22x\"}"}"#;

    fn cipher(json: &str) -> Cipher {
        serde_json::from_str(json).unwrap()
    }

    fn grantor_key(encoded: &str) -> UnsignedSharedKey {
        encoded.parse().unwrap()
    }

    #[tokio::test]
    async fn decrypts_legacy_and_blob_ciphers_with_grantor_key() {
        let grantee = Client::init_test_account(test_bitwarden_com_account_v2()).await;
        let blob = cipher(TEST_VECTOR_BLOB_CIPHER);
        assert!(try_parse_blob(&blob).is_some());

        // The grantee cannot decrypt with their own user key.
        assert!(
            grantee
                .vault()
                .ciphers()
                .decrypt(blob.clone())
                .await
                .is_err()
        );

        let result = grantee
            .vault()
            .ciphers()
            .decrypt_emergency_access_list(
                grantor_key(TEST_VECTOR_GRANTOR_KEY),
                vec![cipher(TEST_VECTOR_LEGACY_CIPHER), blob],
            )
            .await
            .unwrap();

        let names: Vec<_> = result.successes.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["legacy", "blob"]);
        assert!(result.failures.is_empty());
        for view in &result.successes {
            assert_eq!(
                view.login.as_ref().unwrap().password.as_deref(),
                Some("pass")
            );
        }
    }

    #[tokio::test]
    async fn reports_ciphers_under_other_keys_as_failures() {
        let grantee = Client::init_test_account(test_bitwarden_com_account_v2()).await;

        // Blob decryption fails hard, unlike lenient legacy decryption which nulls out
        // undecryptable fields.
        let result = grantee
            .vault()
            .ciphers()
            .decrypt_emergency_access_list(
                grantor_key(TEST_VECTOR_GRANTOR_KEY),
                vec![
                    cipher(TEST_VECTOR_OTHER_KEY_CIPHER),
                    cipher(TEST_VECTOR_LEGACY_CIPHER),
                ],
            )
            .await
            .unwrap();

        assert_eq!(result.successes.len(), 1);
        assert_eq!(result.successes[0].name, "legacy");
        assert_eq!(result.failures.len(), 1);
    }

    #[tokio::test]
    async fn fails_when_grantor_key_is_not_for_current_user() {
        let grantee = Client::init_test_account(test_bitwarden_com_account_v2()).await;

        let result = grantee
            .vault()
            .ciphers()
            .decrypt_emergency_access_list(
                grantor_key(TEST_VECTOR_WRONG_GRANTOR_KEY),
                vec![cipher(TEST_VECTOR_LEGACY_CIPHER)],
            )
            .await;

        assert!(result.is_err());
    }
}
