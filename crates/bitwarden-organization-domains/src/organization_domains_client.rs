use std::sync::Arc;

use bitwarden_core::{
    ApiError, Client, FromClient, MissingFieldError, OrganizationId, client::ApiConfigurations,
    require,
};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// Errors returned from [`OrganizationDomainsClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum OrganizationDomainsError {
    /// A network request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The server response was missing a required field.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

/// Client for reading an organization's verified domains.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct OrganizationDomainsClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl OrganizationDomainsClient {
    /// Returns the names of every domain the organization has claimed and verified, for example
    /// `example.com`.
    ///
    /// Domains that have been claimed but not yet verified are excluded, since the organization has
    /// not proven ownership of them.
    ///
    /// Requires the Manage Users or Manage SSO permission. Prefer this over the full domains
    /// endpoint when the DNS verification token and verification job metadata are not needed: the
    /// full endpoint requires Manage SSO, and calling it without that permission returns a 401
    /// that clients treat as an invalid access token, logging the user out.
    pub async fn get_verified_domains(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Vec<String>, OrganizationDomainsError> {
        let response = self
            .api_configurations
            .api_client
            .organization_domain_api()
            .get_all_mini(organization_id.into())
            .await?;

        require!(response.data)
            .into_iter()
            .filter(|domain| domain.verified_date.is_some())
            .map(|domain| Ok(require!(domain.domain_name)))
            .collect()
    }
}

/// Extension trait for obtaining an [`OrganizationDomainsClient`] from a [`Client`].
pub trait OrganizationDomainsClientExt {
    /// Returns an [`OrganizationDomainsClient`]
    fn organization_domains(&self) -> OrganizationDomainsClient;
}

impl OrganizationDomainsClientExt for Client {
    fn organization_domains(&self) -> OrganizationDomainsClient {
        OrganizationDomainsClient::from_client(self)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            OrganizationDomainMiniResponseModel,
            OrganizationDomainMiniResponseModelListResponseModel,
        },
    };
    use bitwarden_core::client::ApiConfigurations;

    use super::*;

    fn client_with(
        response: OrganizationDomainMiniResponseModelListResponseModel,
    ) -> OrganizationDomainsClient {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.organization_domain_api
                .expect_get_all_mini()
                .returning(move |_org| Ok(response.clone()))
                .once();
        });

        OrganizationDomainsClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    #[tokio::test]
    async fn get_verified_domains_excludes_unverified_domains() {
        let client = client_with(OrganizationDomainMiniResponseModelListResponseModel {
            object: Some("list".to_string()),
            data: Some(vec![
                OrganizationDomainMiniResponseModel {
                    object: Some("organizationDomainMini".to_string()),
                    domain_name: Some("verified.com".to_string()),
                    verified_date: Some("2026-09-15T00:00:00Z".to_string()),
                },
                OrganizationDomainMiniResponseModel {
                    object: Some("organizationDomainMini".to_string()),
                    domain_name: Some("unverified.com".to_string()),
                    verified_date: None,
                },
            ]),
            continuation_token: None,
        });

        let domains = client
            .get_verified_domains(OrganizationId::new_v4())
            .await
            .unwrap();

        assert_eq!(domains, vec!["verified.com".to_string()]);
    }

    #[tokio::test]
    async fn get_verified_domains_returns_empty_when_the_org_has_none() {
        let client = client_with(OrganizationDomainMiniResponseModelListResponseModel {
            object: Some("list".to_string()),
            data: Some(vec![]),
            continuation_token: None,
        });

        let domains = client
            .get_verified_domains(OrganizationId::new_v4())
            .await
            .unwrap();

        assert!(domains.is_empty());
    }

    #[tokio::test]
    async fn get_verified_domains_errors_when_data_is_missing() {
        let client = client_with(OrganizationDomainMiniResponseModelListResponseModel {
            object: Some("list".to_string()),
            data: None,
            continuation_token: None,
        });

        let result = client.get_verified_domains(OrganizationId::new_v4()).await;

        assert!(matches!(
            result,
            Err(OrganizationDomainsError::MissingField(_))
        ));
    }

    #[tokio::test]
    async fn get_verified_domains_errors_when_a_verified_domain_name_is_missing() {
        let client = client_with(OrganizationDomainMiniResponseModelListResponseModel {
            object: Some("list".to_string()),
            data: Some(vec![OrganizationDomainMiniResponseModel {
                object: Some("organizationDomainMini".to_string()),
                domain_name: None,
                verified_date: Some("2026-09-15T00:00:00Z".to_string()),
            }]),
            continuation_token: None,
        });

        let result = client.get_verified_domains(OrganizationId::new_v4()).await;

        assert!(matches!(
            result,
            Err(OrganizationDomainsError::MissingField(_))
        ));
    }
}
