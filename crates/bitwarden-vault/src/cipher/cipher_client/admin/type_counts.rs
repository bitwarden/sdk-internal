use bitwarden_api_api::{
    apis::ApiClient, models::OrganizationCipherTypeCountResponseModelListResponseModel,
};
use bitwarden_core::{ApiError, MissingFieldError, OrganizationId};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CipherType, cipher_client::admin::CipherAdminClient};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetOrganizationCipherTypeCountsAdminError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

/// The number of organization-owned items of a single [`CipherType`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct OrganizationCipherTypeCountResponse {
    /// The item type.
    pub cipher_type: CipherType,
    /// Number of organization-owned items of this type, including archived and trashed items.
    pub count: u32,
}

/// Get the number of organization-owned items for each item type.
pub async fn get_org_cipher_type_counts(
    org_id: OrganizationId,
    api_client: &ApiClient,
) -> Result<Vec<OrganizationCipherTypeCountResponse>, GetOrganizationCipherTypeCountsAdminError> {
    let response: OrganizationCipherTypeCountResponseModelListResponseModel = api_client
        .ciphers_api()
        .get_organization_cipher_type_counts(Some(org_id.into()))
        .await?;

    response
        .data
        .into_iter()
        .flatten()
        .filter_map(|model| {
            let cipher_type = match model.r#type.ok_or(MissingFieldError("type")) {
                Ok(t) => t,
                Err(e) => return Some(Err(e.into())),
            };
            // Item types this SDK version doesn't know about can't be represented, so they are
            // skipped for forward compatibility with newer servers.
            let cipher_type = CipherType::try_from(cipher_type).ok()?;
            Some(
                model
                    .count
                    .ok_or(MissingFieldError("count").into())
                    .map(|count| OrganizationCipherTypeCountResponse {
                        cipher_type,
                        count: u32::try_from(count).unwrap_or_default(),
                    }),
            )
        })
        .collect()
}

#[bitwarden_ffi::wasm_export]
impl CipherAdminClient {
    /// Fetches the number of organization-owned items for each item type, including archived and
    /// trashed items. Requires permission to read organization items as an admin.
    pub async fn get_org_item_type_counts(
        &self,
        org_id: OrganizationId,
    ) -> Result<Vec<OrganizationCipherTypeCountResponse>, GetOrganizationCipherTypeCountsAdminError>
    {
        get_org_cipher_type_counts(org_id, &self.api_configurations.api_client).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{
        CipherType as ApiCipherType, OrganizationCipherTypeCountResponseModel,
    };

    use super::*;

    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";

    fn entry(
        t: Option<ApiCipherType>,
        count: Option<i32>,
    ) -> OrganizationCipherTypeCountResponseModel {
        OrganizationCipherTypeCountResponseModel {
            object: None,
            r#type: t,
            count,
        }
    }

    fn client_returning(data: Option<Vec<OrganizationCipherTypeCountResponseModel>>) -> ApiClient {
        ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_get_organization_cipher_type_counts()
                .withf(|org_id| *org_id == TEST_ORG_ID.parse().ok())
                .returning(move |_| {
                    Ok(OrganizationCipherTypeCountResponseModelListResponseModel {
                        object: None,
                        data: data.clone(),
                        continuation_token: None,
                    })
                });
        })
    }

    #[tokio::test]
    async fn test_counts_success() {
        let api_client = client_returning(Some(vec![
            entry(Some(ApiCipherType::Login), Some(5)),
            entry(Some(ApiCipherType::SSHKey), Some(0)),
        ]));

        let counts = get_org_cipher_type_counts(TEST_ORG_ID.parse().unwrap(), &api_client)
            .await
            .unwrap();

        assert_eq!(
            counts,
            vec![
                OrganizationCipherTypeCountResponse {
                    cipher_type: CipherType::Login,
                    count: 5
                },
                OrganizationCipherTypeCountResponse {
                    cipher_type: CipherType::SshKey,
                    count: 0
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_counts_empty() {
        let api_client = client_returning(None);

        let counts = get_org_cipher_type_counts(TEST_ORG_ID.parse().unwrap(), &api_client)
            .await
            .unwrap();

        assert!(counts.is_empty());
    }

    #[tokio::test]
    async fn test_counts_skips_unknown_type() {
        let api_client = client_returning(Some(vec![
            entry(Some(ApiCipherType::__Unknown(99)), Some(3)),
            entry(Some(ApiCipherType::Card), Some(2)),
        ]));

        let counts = get_org_cipher_type_counts(TEST_ORG_ID.parse().unwrap(), &api_client)
            .await
            .unwrap();

        assert_eq!(counts.len(), 1);
        assert_eq!(counts[0].cipher_type, CipherType::Card);
    }

    #[tokio::test]
    async fn test_counts_missing_fields() {
        for bad in [
            entry(None, Some(1)),
            entry(Some(ApiCipherType::Login), None),
        ] {
            let api_client = client_returning(Some(vec![bad]));
            let result =
                get_org_cipher_type_counts(TEST_ORG_ID.parse().unwrap(), &api_client).await;
            assert!(matches!(
                result,
                Err(GetOrganizationCipherTypeCountsAdminError::MissingField(_))
            ));
        }
    }
}
