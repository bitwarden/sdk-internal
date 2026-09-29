use bitwarden_api_api::models::EmergencyAccessViewResponseModel;
use bitwarden_core::{ApiError, MissingFieldError, require};
use bitwarden_crypto::{CryptoError, UnsignedSharedKey};
use bitwarden_error::bitwarden_error;
use bitwarden_vault::{Cipher, DecryptCipherResult, DecryptError, VaultParseError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when viewing a grantor's ciphers through emergency access.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessViewError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// The grantor key in the server response is malformed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A cipher in the server response could not be parsed.
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    /// The grantor key could not be decapsulated with the current user's private key.
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl EmergencyAccessClient {
    /// Fetches and decrypts the grantor's ciphers of an approved view-only emergency access.
    ///
    /// The server returns the grantor's user key encapsulated to the current user's public key;
    /// it only lives in the key store while the ciphers are decrypted. Ciphers that fail to
    /// decrypt are returned in `failures`.
    pub async fn view_ciphers(
        &self,
        emergency_access_id: EmergencyAccessId,
    ) -> Result<DecryptCipherResult, EmergencyAccessViewError> {
        let response = self
            .api_configurations
            .api_client
            .emergency_access_api()
            .view_ciphers(emergency_access_id.into())
            .await?;

        let (grantor_key, ciphers) = parse_view(response)?;

        Ok(self
            .ciphers
            .decrypt_list_with_shared_key(grantor_key, ciphers)
            .await?)
    }
}

/// Maps the server response to the grantor key and the ciphers encrypted under it.
fn parse_view(
    response: EmergencyAccessViewResponseModel,
) -> Result<(UnsignedSharedKey, Vec<Cipher>), EmergencyAccessViewError> {
    let grantor_key: UnsignedSharedKey = require!(response.key_encrypted).parse()?;

    let ciphers = response
        .ciphers
        .unwrap_or_default()
        .into_iter()
        .map(Cipher::try_from)
        .collect::<Result<_, _>>()?;

    Ok((grantor_key, ciphers))
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::CipherResponseModel};
    use bitwarden_core::{Client, client::test_accounts::test_bitwarden_com_account_v2};
    use bitwarden_vault::VaultClientExt;

    use super::*;
    use crate::EmergencyAccessClientExt;

    // Recorded with the grantor `test_bitwarden_com_account` and the grantee
    // `test_bitwarden_com_account_v2`. Never regenerate these to make a test pass: a vector that
    // stops decrypting is a backward-compatibility break. Ciphers are in the server's
    // `CipherResponseModel` shape.

    /// Grantor user key encapsulated to the grantee's public key, as the server returns it.
    const TEST_VECTOR_GRANTOR_KEY: &str = "4.bbiAjKYUjktIP1PggRJ+ha+O8M0LxWCNkv2bir5QHIYQnAwtx9X3Cta4j0JFnDS2Zy/UFAzRMCpdLR1DgupZ31lZvAhThC86hDvMMa0h84d7o41Rx9tCvqW1FcziuAA0UEr+Gfkc0+qX5yPFEn2eJ2U+ft9J7rSTTDeha1QIMhYnTf2sD2O0nSWSSPoFNLLg2WKoe9uXC5w+MemcK6x6ogG2T77fDr5trXnK7SoWamAWjhK65bYxYrSIpJOtdCR0O9ZIqiITg0lS0I6ACbiFBpHyo+wb+ZUCieUWrNaBjNHHES2XqEWSVVgz1XL2Q0Vh9XNwwPZLbIWZDxbz8FWqeQ==";
    /// Grantor user key encapsulated to the grantor's own public key.
    const TEST_VECTOR_WRONG_GRANTOR_KEY: &str = "4.PBhgsvKoOu8weZWhRAjPoSrucZneEh0Nc+R3xATSuJQk0GyS+xAagJX3Kh7EuPM2pU2OjGbGJeutDpNbp1EKWyYnPzbgXkMi8VU7dnbT8FmidRr/BcrNdcaNzyzJ06GPnL+wPH047iEhzP6DK7prjd3ufEtRp+x9ZCHPnN/vqzoWJD8AZfbC1c8jQFJSaTV/DfkKrF5rfTH3qoQYUNdfL5HOsbTHM8HTMsR18qtj4w638le1ejsjFFgAihcCdlLRsu6okGWCV6LZK3LyjfzXr/WliJUPV3/lySCHEyZoefK52v3TJ8Xy22Tqo+Y86IA/N/UA58c6tV/Iu1Gv3KQsPA==";
    /// Login "legacy" (password "pass"), legacy field-level encryption under the grantor user key.
    const TEST_VECTOR_LEGACY_CIPHER: &str = r#"{"id":null,"organizationId":null,"folderId":null,"key":null,"name":"2.464q0KbAxs3hIhCJ6O/Xxw==|Kwcifl1PAd2KsD4o6nlFdQ==|HrJmneai/21EDb9OmTTQct6b3/nn3ivCIU5SqW0/in4=","notes":null,"type":1,"login":{"username":"2.8e+rqQTBrICEiROAaFShsg==|LlnpGmz/4Vz+/qvVvKeFHA==|1a5pAef2hhJfNFhj45Nok8Boq+wfLC70s3ss/Bbze0s=","password":"2.SPnq6YStUb41/JwNrW8gtA==|12wZdM4ieSJJZnBHo3KWlg==|WIleZuG8RdHQNV3DCWWUL3phwDU83W+7igU2E2LYSJA=","passwordRevisionDate":null,"uris":null,"totp":null,"autofillOnPageLoad":null,"fido2Credentials":null},"identity":null,"card":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"favorite":false,"reprompt":0,"organizationUseTotp":false,"edit":true,"permissions":null,"viewPassword":true,"attachments":null,"fields":null,"passwordHistory":null,"creationDate":"2024-01-01T00:00:00Z","deletedDate":null,"revisionDate":"2024-01-01T00:00:00Z","archivedDate":null,"data":null}"#;
    /// Login "blob" (password "pass"), blob encryption under the grantor user key.
    const TEST_VECTOR_BLOB_CIPHER: &str = r#"{"id":null,"organizationId":null,"folderId":null,"key":"2.Mup/pT+Qs7w8ypIQHNDPeg==|MwjPTr4GrhCD1QA5fntk3XzCduTHKeY8YFEpDceoolLboLE+7rb8rTGWqf2QJVAUxqgtCejT6J1w55YormzjYEP1pTbP1onXYNTnyeyjk1s=|W35zL1xvXDRD9YB0QFV98lAi/qAp+MvAgII1upUrujc=","name":null,"notes":null,"type":1,"login":null,"identity":null,"card":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"favorite":false,"reprompt":0,"organizationUseTotp":false,"edit":true,"permissions":null,"viewPassword":true,"attachments":null,"fields":null,"passwordHistory":null,"creationDate":"2024-01-01T00:00:00Z","deletedDate":null,"revisionDate":"2024-01-01T00:00:00Z","archivedDate":null,"data":"{\"format_version\":1,\"wrapped_cek\":\"2.tI8VAPnduRNp5mqrhGAozQ==|NYgnD7bpK8lRRKm8Xp66YSdpETrLDYZhfDDLTCCmm+NReNPwUEH+PNCWiDmupXA25MHipVR+taGO5+fQgDUDMB+wYZhki3QWvigxV+EO9LA=|UdjlfQgWLtkdHEykgWl05c2Km0OJDaXq56LRSveiRp0=\",\"envelope\":\"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUNb+5HvtZQFf1MDlluqcjhk6AAE4gQI6AAE4gAGhBUzcWa1lfmjYjNurpWhYl8LLSI7A4ZZjiUj92GFVFiH4CyzpSWdrEpmYv9e7MKsupI+nJJbO8BrPGkSepord8QKA0TNDbkPtVNpwgqkSDlKJ0Kx2nLGMA4S/RdfouKJZRpyv6hUV4gMRUF2zC8DWUhIQTBXm81l6b2aMGe0zLe9Jd4ZTxNREt0PIot8+dE4559EPpfN/DPl7VeXZNHKJzGIW56fXYac=\"}"}"#;
    /// Login "other", blob encryption under a key unrelated to the grantor.
    const TEST_VECTOR_OTHER_KEY_CIPHER: &str = r#"{"id":null,"organizationId":null,"folderId":null,"key":"2.hpRJrOTB+2Nmiy5CgVujjA==|XwGLovy+DP7oVIUw6uS/FO3tKjVxloggdd3SS/hyXkl4jOTz4wj+sKtNRfQBClZ0gxhA9xB2G4H3k/FSVr3ZKN8I31AQvJaFmYJb/QnKRok=|xAJygGDtWjsDDEwEIsBQOqk8dsfWmdpFvJchbA+CXLs=","name":null,"notes":null,"type":1,"login":null,"identity":null,"card":null,"secureNote":null,"sshKey":null,"bankAccount":null,"driversLicense":null,"passport":null,"favorite":false,"reprompt":0,"organizationUseTotp":false,"edit":true,"permissions":null,"viewPassword":true,"attachments":null,"fields":null,"passwordHistory":null,"creationDate":"2024-01-01T00:00:00Z","deletedDate":null,"revisionDate":"2024-01-01T00:00:00Z","archivedDate":null,"data":"{\"format_version\":1,\"wrapped_cek\":\"2.5blC2aAA8CSG9+0TGwM8kQ==|N8agG47rDOKXfad8IRXiBYn4sdSqIRblOBG3cTmF4MNatMWMyNQ1eiBI3ESwXFGckSWXDWDiIYjcA5PtSTuZD3TMHbEViA35ETPyZ3p7TQk=|+JAq5PcDmGn33DroTbFHNVk2foKW0zD+0ciiZgK2R+4=\",\"envelope\":\"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUH+IGveCBNLVKkWxFC6Cj8A6AAE4gQI6AAE4gAGhBUwhbDAGkN2AhbXVNQtYmOEmXbdcL1B2nsuoI906sAHORuyQu19HsuQzu/bZiOyuHGR/f5Vi0EOhVa0+AhHZoUGI29BE+PgJOnVjuHk25z8j7XHqiw4qt+CKcbJRR6o2RC5QUgEvFl1M9+3P9wuVkijs7hu8CaCjcyyGGA3KnN3vJ5EXP4oqtteamB1jyHx9PxXV2ZuCQVDsFb6bMoO/bnBhTSuLe22x\"}"}"#;

    const TEST_EMERGENCY_ACCESS_ID: &str = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";

    fn cipher_response(json: &str) -> CipherResponseModel {
        serde_json::from_str(json).unwrap()
    }

    /// Creates the grantee client whose API returns the given view response.
    async fn grantee(key_encrypted: Option<&str>, ciphers: &[&str]) -> Client {
        let response = EmergencyAccessViewResponseModel {
            object: None,
            key_encrypted: key_encrypted.map(str::to_owned),
            ciphers: Some(ciphers.iter().map(|c| cipher_response(c)).collect()),
        };

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.emergency_access_api
                .expect_view_ciphers()
                .withf(|id| id.to_string() == TEST_EMERGENCY_ACCESS_ID)
                .returning(move |_| Ok(response.clone()))
                .once();
        });

        Client::init_test_account_with_api_client(test_bitwarden_com_account_v2(), api_client).await
    }

    async fn view(client: &Client) -> Result<DecryptCipherResult, EmergencyAccessViewError> {
        client
            .emergency_access()
            .view_ciphers(TEST_EMERGENCY_ACCESS_ID.parse().unwrap())
            .await
    }

    #[tokio::test]
    async fn decrypts_legacy_and_blob_ciphers_with_grantor_key() {
        let client = grantee(
            Some(TEST_VECTOR_GRANTOR_KEY),
            &[TEST_VECTOR_LEGACY_CIPHER, TEST_VECTOR_BLOB_CIPHER],
        )
        .await;

        // The grantee cannot decrypt with their own user key.
        let blob = Cipher::try_from(cipher_response(TEST_VECTOR_BLOB_CIPHER)).unwrap();
        assert!(client.vault().ciphers().decrypt(blob).await.is_err());

        let result = view(&client).await.unwrap();

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
        // Blob decryption fails hard, unlike lenient legacy decryption which nulls out
        // undecryptable fields.
        let client = grantee(
            Some(TEST_VECTOR_GRANTOR_KEY),
            &[TEST_VECTOR_OTHER_KEY_CIPHER, TEST_VECTOR_LEGACY_CIPHER],
        )
        .await;

        let result = view(&client).await.unwrap();

        assert_eq!(result.successes.len(), 1);
        assert_eq!(result.successes[0].name, "legacy");
        assert_eq!(result.failures.len(), 1);
    }

    #[tokio::test]
    async fn fails_when_grantor_key_is_not_for_current_user() {
        let client = grantee(
            Some(TEST_VECTOR_WRONG_GRANTOR_KEY),
            &[TEST_VECTOR_LEGACY_CIPHER],
        )
        .await;

        let result = view(&client).await;

        assert!(matches!(result, Err(EmergencyAccessViewError::Decrypt(_))));
    }

    #[tokio::test]
    async fn fails_when_grantor_key_is_malformed() {
        let client = grantee(Some("not a key"), &[TEST_VECTOR_LEGACY_CIPHER]).await;

        let result = view(&client).await;

        assert!(matches!(result, Err(EmergencyAccessViewError::Crypto(_))));
    }

    #[tokio::test]
    async fn fails_when_grantor_key_is_missing() {
        let client = grantee(None, &[TEST_VECTOR_LEGACY_CIPHER]).await;

        let result = view(&client).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessViewError::MissingField(_))
        ));
    }
}
