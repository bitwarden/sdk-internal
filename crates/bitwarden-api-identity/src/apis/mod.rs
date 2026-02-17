// Reexport base types from bitwarden-api-base for backwards compatibility
pub use bitwarden_api_base::*;

pub mod accounts_api;
pub mod info_api;
pub mod sso_api;

// Reexport Configuration type from bitwarden-api-base for backwards compatibility
pub mod configuration {
    pub use bitwarden_api_base::Configuration;
}

use std::sync::Arc;

#[allow(clippy::large_enum_variant, private_interfaces)]
pub enum ApiClient {
    Real(ApiClientReal),
    #[cfg(feature = "mockall")]
    Mock(ApiClientMock),
}

struct ApiClientReal {
    accounts_api: accounts_api::AccountsApiClient,
    info_api: info_api::InfoApiClient,
    sso_api: sso_api::SsoApiClient,
}

#[cfg(feature = "mockall")]
pub struct ApiClientMock {
    pub accounts_api: accounts_api::MockAccountsApi,
    pub info_api: info_api::MockInfoApi,
    pub sso_api: sso_api::MockSsoApi,
}

impl ApiClient {
    pub fn new(configuration: &Arc<bitwarden_api_base::Configuration>) -> Self {
        Self::Real(ApiClientReal {
            accounts_api: accounts_api::AccountsApiClient::new(configuration.clone()),
            info_api: info_api::InfoApiClient::new(configuration.clone()),
            sso_api: sso_api::SsoApiClient::new(configuration.clone()),
        })
    }

    #[cfg(feature = "mockall")]
    pub fn new_mocked(func: impl FnOnce(&mut ApiClientMock)) -> Self {
        let mut mock = ApiClientMock {
            accounts_api: accounts_api::MockAccountsApi::new(),
            info_api: info_api::MockInfoApi::new(),
            sso_api: sso_api::MockSsoApi::new(),
        };
        func(&mut mock);
        Self::Mock(mock)
    }
}

impl ApiClient {
    pub fn accounts_api(&self) -> &dyn accounts_api::AccountsApi {
        match self {
            ApiClient::Real(real) => &real.accounts_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.accounts_api,
        }
    }
    pub fn info_api(&self) -> &dyn info_api::InfoApi {
        match self {
            ApiClient::Real(real) => &real.info_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.info_api,
        }
    }
    pub fn sso_api(&self) -> &dyn sso_api::SsoApi {
        match self {
            ApiClient::Real(real) => &real.sso_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.sso_api,
        }
    }
}
