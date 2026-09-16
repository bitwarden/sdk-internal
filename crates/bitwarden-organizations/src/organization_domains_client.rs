use std::sync::Arc;

use bitwarden_api_api::models::OrganizationDomainMiniResponseModel;
use bitwarden_core::{ApiError, Client, FromClient, OrganizationId, client::ApiConfigurations};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// Errors returned from [`OrganizationDomainsClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum OrganizationDomainsError {
    /// A network request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// A domain claimed by an organization.
///
/// This is the slim view of a claimed domain: it carries no DNS verification token and no
/// verification job metadata, so it is safe to expose to members who administer the organization
/// without granting them visibility into its SSO configuration.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct ClaimedDomain {
    /// The claimed domain name, for example `example.com`.
    pub domain_name: String,
    /// Whether the organization has proven ownership of the domain via its DNS TXT record.
    pub verified: bool,
}

impl From<OrganizationDomainMiniResponseModel> for ClaimedDomain {
    fn from(response: OrganizationDomainMiniResponseModel) -> Self {
        ClaimedDomain {
            domain_name: response.domain_name.unwrap_or_default(),
            verified: response.verified_date.is_some(),
        }
    }
}

/// Client for reading an organization's claimed domains.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct OrganizationDomainsClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl OrganizationDomainsClient {
    /// Returns every domain the organization has claimed, along with whether each one has been
    /// verified.
    ///
    /// Requires the Manage Users or Manage SSO permission. Prefer this over the full domains
    /// endpoint when the DNS verification token and verification job metadata are not needed: the
    /// full endpoint requires Manage SSO, and calling it without that permission returns a 401
    /// that clients treat as an invalid access token, logging the user out.
    pub async fn get_claimed_domains(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Vec<ClaimedDomain>, OrganizationDomainsError> {
        let response = self
            .api_configurations
            .api_client
            .organization_domain_api()
            .get_all_mini(organization_id.into())
            .await?;

        Ok(response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(ClaimedDomain::from)
            .collect())
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
        apis::ApiClient, models::OrganizationDomainMiniResponseModelListResponseModel,
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
    async fn get_claimed_domains_maps_verification_status() {
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
            .get_claimed_domains(OrganizationId::new_v4())
            .await
            .unwrap();

        assert_eq!(
            domains,
            vec![
                ClaimedDomain {
                    domain_name: "verified.com".to_string(),
                    verified: true,
                },
                ClaimedDomain {
                    domain_name: "unverified.com".to_string(),
                    verified: false,
                },
            ]
        );
    }

    #[tokio::test]
    async fn get_claimed_domains_returns_empty_when_the_org_has_none() {
        let client = client_with(OrganizationDomainMiniResponseModelListResponseModel {
            object: Some("list".to_string()),
            data: Some(vec![]),
            continuation_token: None,
        });

        let domains = client
            .get_claimed_domains(OrganizationId::new_v4())
            .await
            .unwrap();

        assert!(domains.is_empty());
    }
}
