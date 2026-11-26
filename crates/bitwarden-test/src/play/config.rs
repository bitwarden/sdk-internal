//! Configuration for the Play test framework
//!
//! Environment variables:
//! - `BITWARDEN_API_URL`: Base API URL (default: `https://localhost:8080/api`)
//! - `BITWARDEN_IDENTITY_URL`: Identity URL (default: `https://localhost:8080/identity`)
//! - `BITWARDEN_SEEDER_URL`: Seeder API URL (defaults to `http://localhost:5047`)
//! - `BITWARDEN_SEEDER_USERNAME` / `BITWARDEN_SEEDER_PASSWORD`: HTTP basic auth credentials for the
//!   Seeder API (the `seederSettings` account). Both must be set for them to be used.

use std::{env, fmt};

/// HTTP basic auth credentials for the Seeder API.
///
/// The password is never included in `Debug` output.
#[derive(Clone)]
pub struct SeederCredentials {
    pub(crate) username: String,
    pub(crate) password: String,
}

impl SeederCredentials {
    /// Create credentials from a username and password
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl fmt::Debug for SeederCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeederCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Configuration for connecting to Bitwarden services during E2E tests
#[derive(Debug, Clone)]
pub struct PlayConfig {
    /// Base API URL
    pub api_url: String,
    /// Identity URL for authentication
    pub identity_url: String,
    /// Seeder API URL for test data management
    pub seeder_url: String,
    /// Optional HTTP basic auth credentials for the Seeder API
    pub seeder_credentials: Option<SeederCredentials>,
}

impl PlayConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let api_url = env::var("BITWARDEN_API_URL")
            .unwrap_or_else(|_| "https://localhost:8080/api".to_string());

        let identity_url = env::var("BITWARDEN_IDENTITY_URL")
            .unwrap_or_else(|_| "https://localhost:8080/identity".to_string());

        // TODO: Should use the web proxy once available
        let seeder_url = env::var("BITWARDEN_SEEDER_URL")
            .unwrap_or_else(|_| "http://localhost:5047".to_string());

        let seeder_credentials = match (
            env::var("BITWARDEN_SEEDER_USERNAME"),
            env::var("BITWARDEN_SEEDER_PASSWORD"),
        ) {
            (Ok(username), Ok(password)) => Some(SeederCredentials::new(username, password)),
            _ => None,
        };

        Self {
            api_url,
            identity_url,
            seeder_url,
            seeder_credentials,
        }
    }

    /// Create a new configuration with custom URLs
    pub fn new(
        api_url: impl Into<String>,
        identity_url: impl Into<String>,
        seeder_url: impl Into<String>,
    ) -> Self {
        Self {
            api_url: api_url.into(),
            identity_url: identity_url.into(),
            seeder_url: seeder_url.into(),
            seeder_credentials: None,
        }
    }

    /// Set the HTTP basic auth credentials used for every Seeder API request
    pub fn with_seeder_credentials(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.seeder_credentials = Some(SeederCredentials::new(username, password));
        self
    }
}

impl Default for PlayConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_config_with_custom_urls() {
        let config = PlayConfig::new(
            String::from("https://api.example.com"),
            "https://identity.example.com",
            "http://seeder.example.com",
        );

        assert_eq!(config.api_url, "https://api.example.com");
        assert_eq!(config.identity_url, "https://identity.example.com");
        assert_eq!(config.seeder_url, "http://seeder.example.com");
    }

    #[test]
    fn test_debug_does_not_leak_seeder_password() {
        let config = PlayConfig::new("https://api", "https://identity", "http://seeder")
            .with_seeder_credentials("seeder-user", "hunter2-secret");

        let debug = format!("{config:?}");
        assert!(!debug.contains("hunter2-secret"));
        assert!(debug.contains("seeder-user"));
    }
}
