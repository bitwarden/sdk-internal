//! Configuration for the Play test framework
//!
//! Environment variables:
//! - `BITWARDEN_API_URL`: Base API URL (default: `https://localhost:8080/api`)
//! - `BITWARDEN_IDENTITY_URL`: Identity URL (default: `https://localhost:8080/identity`)
//! - `BITWARDEN_SEEDER_URL`: Seeder API URL (defaults to `http://localhost:5047`)

use std::env;

/// Configuration for connecting to Bitwarden services during E2E tests
#[derive(Debug, Clone)]
pub struct PlayConfig {
    /// Base API URL
    pub api_url: String,
    /// Identity URL for authentication
    pub identity_url: String,
    /// Seeder API URL for test data management
    pub seeder_url: String,
}

impl PlayConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let api_url = env::var("BITWARDEN_API_URL")
            .unwrap_or_else(|_| "https://localhost:8080/api".to_string());

        let identity_url = env::var("BITWARDEN_IDENTITY_URL")
            .unwrap_or_else(|_| "https://localhost:8080/identity".to_string());

        let seeder_url = env::var("BITWARDEN_SEEDER_URL")
            .unwrap_or_else(|_| "http://localhost:5047".to_string());

        Self {
            api_url,
            identity_url,
            seeder_url,
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
        }
    }
}

impl Default for PlayConfig {
    fn default() -> Self {
        Self::from_env()
    }
}
