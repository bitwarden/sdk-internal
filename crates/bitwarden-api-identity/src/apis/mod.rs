use std::{error, fmt};

#[derive(Debug, Clone)]
pub struct ResponseContent<T> {
    pub status: reqwest::StatusCode,
    pub content: String,
    pub entity: Option<T>,
}

#[derive(Debug)]
pub enum Error<T> {
    Reqwest(reqwest::Error),
    Serde(serde_json::Error),
    Io(std::io::Error),
    ResponseError(ResponseContent<T>),
}

impl<T> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (module, e) = match self {
            Error::Reqwest(e) => ("reqwest", e.to_string()),
            Error::Serde(e) => ("serde", e.to_string()),
            Error::Io(e) => ("IO", e.to_string()),
            Error::ResponseError(e) => ("response", format!("status code {}", e.status)),
        };
        write!(f, "error in {}: {}", module, e)
    }
}

impl<T: fmt::Debug> error::Error for Error<T> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            Error::Reqwest(e) => e,
            Error::Serde(e) => e,
            Error::Io(e) => e,
            Error::ResponseError(_) => return None,
        })
    }
}

impl<T> From<reqwest::Error> for Error<T> {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl<T> From<serde_json::Error> for Error<T> {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl<T> From<std::io::Error> for Error<T> {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub fn urlencode<T: AsRef<str>>(s: T) -> String {
    ::url::form_urlencoded::byte_serialize(s.as_ref().as_bytes()).collect()
}

pub fn parse_deep_object(prefix: &str, value: &serde_json::Value) -> Vec<(String, String)> {
    if let serde_json::Value::Object(object) = value {
        let mut params = vec![];

        for (key, value) in object {
            match value {
                serde_json::Value::Object(_) => params.append(&mut parse_deep_object(
                    &format!("{}[{}]", prefix, key),
                    value,
                )),
                serde_json::Value::Array(array) => {
                    for (i, value) in array.iter().enumerate() {
                        params.append(&mut parse_deep_object(
                            &format!("{}[{}][{}]", prefix, key, i),
                            value,
                        ));
                    }
                }
                serde_json::Value::String(s) => {
                    params.push((format!("{}[{}]", prefix, key), s.clone()))
                }
                _ => params.push((format!("{}[{}]", prefix, key), value.to_string())),
            }
        }

        return params;
    }

    unimplemented!("Only objects are supported with style=deepObject")
}

/// Internal use only
/// A content type supported by this client.
#[expect(dead_code)]
enum ContentType {
    Json,
    Text,
    Unsupported(String),
}

impl From<&str> for ContentType {
    fn from(content_type: &str) -> Self {
        if content_type.starts_with("application") && content_type.contains("json") {
            return Self::Json;
        } else if content_type.starts_with("text/plain") {
            return Self::Text;
        } else {
            return Self::Unsupported(content_type.to_string());
        }
    }
}

pub mod accounts_api;
pub mod info_api;
pub mod sso_api;

pub mod configuration;

use std::sync::Arc;

#[expect(clippy::large_enum_variant, private_interfaces)]
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
    pub fn new(configuration: &Arc<configuration::Configuration>) -> Self {
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
