use std::sync::Arc;

use crate::apis::configuration::Configuration;

pub mod configuration;
pub mod user_keys_api;

#[derive(Debug, Clone)]
pub struct ResponseContent {
    pub status: reqwest::StatusCode,
    pub content: String,
}

#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    ReqwestMiddleware(reqwest_middleware::Error),
    Serde(serde_json::Error),
    Io(std::io::Error),
    ResponseError(ResponseContent),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<reqwest_middleware::Error> for Error {
    fn from(e: reqwest_middleware::Error) -> Self {
        Error::ReqwestMiddleware(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

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
