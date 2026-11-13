use std::sync::Arc;

use bitwarden_api_base::Configuration;
pub use bitwarden_api_base::{Error, ResponseContent};

pub mod user_keys_api;

pub enum ApiClient {
    Real(ApiClientReal),
    Mock(ApiClientMock),
}

pub struct ApiClientReal {
    user_keys_api: user_keys_api::UserKeysApiClient,
}

pub struct ApiClientMock {
    pub user_keys_api: user_keys_api::MockUserKeysApi,
}

impl ApiClient {
    pub fn new(configuration: &Arc<Configuration>) -> Self {
        Self::Real(ApiClientReal {
            user_keys_api: user_keys_api::UserKeysApiClient::new(configuration.clone()),
        })
    }

    pub fn new_mocked(func: impl FnOnce(&mut ApiClientMock)) -> Self {
        let mut mock = ApiClientMock {
            user_keys_api: user_keys_api::MockUserKeysApi::new(),
        };
        func(&mut mock);
        Self::Mock(mock)
    }

    pub fn user_keys_api(&self) -> &dyn user_keys_api::UserKeysApi {
        match self {
            ApiClient::Real(real) => &real.user_keys_api,
            ApiClient::Mock(mock) => &mock.user_keys_api,
        }
    }
}
