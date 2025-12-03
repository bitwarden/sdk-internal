use bitwarden_api_api::models::CipherBulkDeleteRequestModel;
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{ApiError, OrganizationId};
use wasm_bindgen::prelude::*;

use crate::{
    CipherId, CipherView, CiphersClient,
    cipher_client::{
        create::{CipherCreateRequest, CreateCipherError},
        delete::DeleteCipherError,
        edit::{CipherEditRequest, EditCipherError},
    },
};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CipherAdminClient {
    pub(crate) client: CiphersClient,
}

impl CipherAdminClient {
    /// Creates a new [Cipher] for an organization, using the admin server endpoints endpoints.
    pub async fn create_as_admin(
        &self,
        request: CipherCreateRequest,
        collection_ids: Vec<CollectionId>,
    ) -> Result<CipherView, CreateCipherError> {
        self.client
            .create_cipher(request, collection_ids, true)
            .await
    }

    // putCipherAdmin(id, request: CipherRequest)
    // ciphers_id_admin_put
    #[allow(missing_docs)] // 
    pub async fn edit_as_admin(
        &self,
        request: CipherEditRequest,
    ) -> Result<CipherView, EditCipherError> {
        self.client.edit_internal(request, true).await
    }

    /// Deletes the [Cipher] with the matching [CipherId] from the server, using the admin endpoint.
    pub async fn delete_as_admin(&self, cipher_id: CipherId) -> Result<(), ApiError> {
        let configs = self.client.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.delete_admin(cipher_id.into()).await?;
        Ok(())
    }

    /// Soft-deletes the [Cipher] with the matching [CipherId] from the server, using the admin
    /// endpoint.
    pub async fn soft_delete_as_admin(&self, cipher_id: CipherId) -> Result<(), DeleteCipherError> {
        let configs = self.client.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.put_delete_admin(cipher_id.into()).await?;
        Ok(())
    }

    /// Deletes all [Cipher] objects with a matching [CipherId] from the server, using the admin
    /// endpoint.
    pub async fn delete_many_as_admin(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<(), DeleteCipherError> {
        let configs = self.client.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.delete_many_admin(Some(CipherBulkDeleteRequestModel {
            ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
            organization_id: organization_id.map(|id| id.to_string()),
        }))
        .await?;
        Ok(())
    }

    /// Soft-deletes all [Cipher] objects for the given [CipherId]s from the server, using the admin
    /// endpoint.
    pub async fn soft_delete_many_as_admin(
        &self,
        cipher_ids: Vec<CipherId>,
        organization_id: Option<OrganizationId>,
    ) -> Result<(), DeleteCipherError> {
        let configs = self.client.get_api_configurations().await;
        let api = configs.api_client.ciphers_api();
        api.put_delete_many_admin(Some(CipherBulkDeleteRequestModel {
            ids: cipher_ids.into_iter().map(|id| id.to_string()).collect(),
            organization_id: organization_id.map(|id| id.to_string()),
        }))
        .await?;
        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     #[tokio::test]
//     async fn test_edit_cipher_as_admin() {
//         let (mock_server, _config) = start_api_mock(vec![
//             Mock::given(method("PUT"))
//                 .and(path_regex(r"/ciphers/[a-f0-9-]+"))
//                 .respond_with(move |req: &wiremock::Request| {
//                     let body_bytes = req.body.as_slice();
//                     let request_body: CipherRequestModel =
//                         serde_json::from_slice(body_bytes).expect("Failed to parse request
// body");

//                     let response = CipherResponseModel {
//                         id: Some(TEST_CIPHER_ID.try_into().unwrap()),
//                         organization_id: request_body
//                             .organization_id
//                             .and_then(|id| id.parse().ok()),
//                         name: Some(request_body.name.clone()),
//                         r#type: request_body.r#type,
//                         creation_date: Some(Utc::now().to_string()),
//                         revision_date: Some(Utc::now().to_string()),
//                         ..Default::default()
//                     };

//                     ResponseTemplate::new(200).set_body_json(&response)
//                 }),
//         ])
//         .await;
//         let client = create_client_with_wiremock(&mock_server).await;
//         let repository = client.get_repository().unwrap();

//         let cipher_view = generate_test_cipher();
//         repository
//             .set(
//                 TEST_CIPHER_ID.to_string(),
//                 client.encrypt(cipher_view.clone()).unwrap().cipher,
//             )
//             .await
//             .unwrap();

//         let request = cipher_view.try_into().unwrap();
//         let start_time = Utc::now();
//         let result = client.edit_as_admin(request).await.unwrap();

//         let cipher = repository.get(TEST_CIPHER_ID.to_string()).await.unwrap();
//         // Should not update local repository for admin endpoints.
//         assert!(result.revision_date > start_time);
//         assert!(cipher.unwrap().revision_date < start_time);

//         assert_eq!(result.id, TEST_CIPHER_ID.parse().ok());
//         assert_eq!(result.name, "Test Login");
//     }
// }

// #[tokio::test]
// async fn test_create_cipher_as_admin() {
//     let (mock_server, _config) = start_api_mock(vec![
//         Mock::given(method("POST"))
//             .and(path(r"/ciphers/admin"))
//             .respond_with(move |req: &wiremock::Request| {
//                 let body_bytes = req.body.as_slice();
//                 let request_body: CipherCreateRequestModel =
//                     serde_json::from_slice(body_bytes).expect("Failed to parse request body");

//                 let response = CipherResponseModel {
//                     id: Some(TEST_CIPHER_ID.try_into().unwrap()),
//                     organization_id: request_body
//                         .cipher
//                         .organization_id
//                         .and_then(|id| id.parse().ok()),
//                     name: Some(request_body.cipher.name.clone()),
//                     r#type: request_body.cipher.r#type,
//                     creation_date: Some(Utc::now().to_string()),
//                     revision_date: Some(Utc::now().to_string()),
//                     ..Default::default()
//                 };

//                 ResponseTemplate::new(200).set_body_json(&response)
//             }),
//     ])
//     .await;

//     let client = create_client_with_wiremock(&mock_server).await;
//     let response = client
//         .create_as_admin(
//             CipherCreateRequest {
//                 organization_id: Some(TEST_ORG_ID.parse().unwrap()),
//                 folder_id: None,
//                 name: "Test Cipher".into(),
//                 notes: None,
//                 favorite: false,
//                 reprompt: CipherRepromptType::None,
//                 r#type: CipherViewType::Login(LoginView {
//                     username: None,
//                     password: None,
//                     password_revision_date: None,
//                     uris: None,
//                     totp: None,
//                     autofill_on_page_load: None,
//                     fido2_credentials: None,
//                 }),
//                 fields: vec![],
//             },
//             vec![TEST_COLLECTION_ID.parse().unwrap()],
//         )
//         .await
//         .unwrap();

//     let repository = client.get_repository().unwrap();
//     let cipher = repository.get(TEST_CIPHER_ID.to_string()).await.unwrap();
//     // Should not update local repository for admin endpoints.
//     assert!(cipher.is_none());

//     assert_eq!(response.id, Some(TEST_CIPHER_ID.parse().unwrap()));
//     assert_eq!(response.organization_id, Some(TEST_ORG_ID.parse().unwrap()));
// }
