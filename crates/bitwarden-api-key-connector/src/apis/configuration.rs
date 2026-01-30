#[derive(Debug, Clone)]
pub struct Configuration {
    pub base_path: String,
    pub user_agent: Option<String>,
    pub client: reqwest_middleware::ClientWithMiddleware,
    pub oauth_access_token: Option<String>,
}

impl Configuration {
    pub fn new() -> Configuration {
        Configuration::default()
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            base_path: "https://key-connector.bitwarden.com".to_owned(),
            user_agent: Some("api/key-connector/rust".to_owned()),
            client: reqwest::Client::new().into(),
            oauth_access_token: None,
        }
    }
}
