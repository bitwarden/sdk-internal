//! CLI state management and persistence.
//!
//! This module provides persistent storage for CLI-specific data using the SDK's
//! repository pattern with SQLite backend.
//!
//! # Architecture
//!
//! - **Storage Location**: `~/.config/bitwarden-cli/bw.sqlite` (Unix) or
//!   `%APPDATA%\bitwarden-cli\bw.sqlite` (Windows)
//! - **Database**: Single SQLite database for all CLI state
//! - **Repository Pattern**: Uses SDK's `Repository<T>` trait with type-safe access
//! - **Migrations**: Migration-based schema evolution via `RepositoryMigrations`
//!
//! # Security
//!
//! - Database protected by OS file permissions (0600 on Unix)
//! - No encryption at rest in current implementation
//! - Contains sensitive data: tokens, credentials, login methods
//!
//! # Usage
//!
//! 1. Call [`initialize_database`] once at startup (idempotent)
//! 2. Use domain modules for type-safe state access

use std::path::PathBuf;

use bitwarden_core::Client;
use bitwarden_pm::migrations::get_sdk_managed_migrations;
use bitwarden_state::DatabaseConfiguration;
use thiserror::Error;
use tracing::debug;

/// Errors that can occur during state operations.
#[derive(Debug, Error)]
pub enum StateError {
    /// Config directory not found (HOME or APPDATA not set).
    #[error("Config directory not found (HOME or APPDATA environment variable not set)")]
    ConfigDirNotFound,

    /// IO error during file operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Repository operation failed.
    #[error(transparent)]
    Repository(#[from] bitwarden_state::repository::RepositoryError),

    /// State registry operation failed.
    #[error(transparent)]
    Registry(#[from] bitwarden_state::registry::StateRegistryError),

    /// Settings operation failed.
    #[error(transparent)]
    Settings(#[from] bitwarden_state::SettingsError),

    /// Auth state not available in client.
    #[error("Auth state not available in client")]
    NoAuthState,

    /// Required state not found.
    #[error("{0}")]
    NotFound(&'static str),

    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    /// Data envelope error.
    #[error("Data envelope error: {0}")]
    DataEnvelope(#[from] bitwarden_crypto::safe::DataEnvelopeError),

    /// Invalid base64 encoding.
    #[error("Invalid base64 encoding")]
    InvalidBase64(#[from] bitwarden_encoding::NotB64EncodedError),

    /// Crypto client error.
    #[error("Crypto client error: {0}")]
    CryptoClient(#[from] bitwarden_core::key_management::crypto::CryptoClientError),

    /// Encryption settings error.
    #[error("Encryption settings error: {0}")]
    EncryptionSettings(
        #[from] bitwarden_core::client::encryption_settings::EncryptionSettingsError,
    ),

    /// User ID not available.
    #[error("No authenticated user")]
    NoUserId,

    /// Session key belongs to different user.
    #[error("Session key belongs to different user")]
    UserMismatch,
}

/// Get the database configuration for the CLI
fn get_database_config() -> Result<DatabaseConfiguration, StateError> {
    let config_dir = ensure_config_dir()?;

    Ok(DatabaseConfiguration::Sqlite {
        db_name: "bw".to_string(),
        folder_path: config_dir,
    })
}

/// Get the full database path
pub(crate) fn get_database_path() -> Result<PathBuf, StateError> {
    let config_dir = get_config_dir()?;
    // The .sqlite extension is added by bitwarden-state
    Ok(config_dir.join("bw.sqlite"))
}

/// Get the CLI config directory
fn get_config_dir() -> Result<PathBuf, StateError> {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").map_err(|_| StateError::ConfigDirNotFound)?;
        Ok(PathBuf::from(appdata).join("bitwarden-cli"))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").map_err(|_| StateError::ConfigDirNotFound)?;
        Ok(PathBuf::from(home).join(".config").join("bitwarden-cli"))
    }
}

/// Ensure config directory exists with proper permissions
fn ensure_config_dir() -> Result<PathBuf, StateError> {
    let dir = get_config_dir()?;
    std::fs::create_dir_all(&dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&dir, perms)?;
    }

    Ok(dir)
}

/// Initialize the CLI database
/// This is idempotent - safe to call multiple times
pub(crate) async fn initialize_database(client: &Client) -> Result<(), StateError> {
    let config = get_database_config()?;
    let migrations = get_sdk_managed_migrations();

    match client
        .platform()
        .state()
        .initialize_database(config, migrations)
        .await
    {
        Ok(()) => Ok(()),
        Err(bitwarden_state::registry::StateRegistryError::DatabaseAlreadyInitialized) => {
            debug!("Database is already initialized");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Delete the database file (for complete cleanup)
#[allow(dead_code)]
fn delete_database() -> Result<(), StateError> {
    let db_path = get_database_path()?;

    if db_path.exists() {
        std::fs::remove_file(&db_path)?;
        debug!("Deleted database: {:?}", db_path);
    }

    Ok(())
}
