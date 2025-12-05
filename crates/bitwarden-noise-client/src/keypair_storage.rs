//! Static keypair storage for persistent device identity
//!
//! Manages Noise Protocol static keypairs that persist across sessions,
//! enabling mutual authentication between devices.

use std::{fs, path::PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use bitwarden_noise::{Keypair, generate_keypair};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::error::RemoteClientError;

/// A stored keypair
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKeypair {
    /// Base64-encoded public key
    public_key: String,
    /// Base64-encoded secret key
    secret_key: String,
    /// Unix timestamp when keypair was created
    created_at: u64,
}

/// Get the directory where static keypairs are stored
fn get_keypair_directory() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".noise-static-keys")
}

/// Get the file path for a device's static keypair
fn get_keypair_path(device_id: &str) -> PathBuf {
    // Sanitize device_id to prevent directory traversal
    let sanitized: String = device_id
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    get_keypair_directory().join(format!("{}.json", sanitized))
}

/// Ensure the keypair storage directory exists
fn ensure_keypair_directory() -> Result<(), RemoteClientError> {
    let dir = get_keypair_directory();
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| {
            RemoteClientError::KeypairStorage(format!("Failed to create keypair directory: {}", e))
        })?;
        info!("Created keypair storage directory: {:?}", dir);
    }
    Ok(())
}

/// Generate and persist a new static keypair for a device
///
/// # Arguments
/// * `device_id` - Unique identifier for the device
///
/// # Returns
/// The generated keypair
pub fn generate_static_keypair(device_id: &str) -> Result<Keypair, RemoteClientError> {
    ensure_keypair_directory()?;

    let keypair = generate_keypair()?;
    let keypair_path = get_keypair_path(device_id);

    let stored = StoredKeypair {
        public_key: STANDARD.encode(keypair.public_key()),
        secret_key: STANDARD.encode(keypair.secret_key()),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };

    let content = serde_json::to_string_pretty(&stored)?;
    fs::write(&keypair_path, content).map_err(|e| {
        error!("Failed to write keypair: {}", e);
        RemoteClientError::KeypairStorage(format!("Failed to write keypair: {}", e))
    })?;

    info!("Generated static keypair for device: {}", device_id);
    Ok(keypair)
}

/// Load an existing static keypair for a device
///
/// # Arguments
/// * `device_id` - Unique identifier for the device
///
/// # Returns
/// The keypair if found, or None
pub fn load_static_keypair(device_id: &str) -> Result<Option<Keypair>, RemoteClientError> {
    let keypair_path = get_keypair_path(device_id);

    if !keypair_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&keypair_path).map_err(|e| {
        error!("Failed to read keypair for device {}: {}", device_id, e);
        RemoteClientError::KeypairStorage(format!("Failed to read keypair: {}", e))
    })?;

    let stored: StoredKeypair = serde_json::from_str(&content).map_err(|e| {
        error!("Failed to parse keypair for device {}: {}", device_id, e);
        RemoteClientError::KeypairStorage(format!("Failed to parse keypair: {}", e))
    })?;

    let public_key = STANDARD.decode(&stored.public_key).map_err(|e| {
        RemoteClientError::KeypairStorage(format!("Invalid public key encoding: {}", e))
    })?;

    let secret_key = STANDARD.decode(&stored.secret_key).map_err(|e| {
        RemoteClientError::KeypairStorage(format!("Invalid secret key encoding: {}", e))
    })?;

    Ok(Some(Keypair::new(public_key, secret_key)))
}

/// Get or create a static keypair for a device
///
/// Loads existing keypair if available, otherwise generates a new one.
///
/// # Arguments
/// * `device_id` - Unique identifier for the device
///
/// # Returns
/// The keypair for the device
pub fn get_or_create_static_keypair(device_id: &str) -> Result<Keypair, RemoteClientError> {
    if let Some(existing) = load_static_keypair(device_id)? {
        debug!("Loaded existing static keypair for device: {}", device_id);
        return Ok(existing);
    }

    info!(
        "No existing keypair found for device: {}, generating new one",
        device_id
    );
    generate_static_keypair(device_id)
}

/// Check if a static keypair exists for a device
pub fn has_static_keypair(device_id: &str) -> bool {
    get_keypair_path(device_id).exists()
}

/// Delete a static keypair for a device
///
/// # Arguments
/// * `device_id` - Unique identifier for the device
///
/// # Returns
/// true if deleted, false if not found
pub fn delete_static_keypair(device_id: &str) -> Result<bool, RemoteClientError> {
    let keypair_path = get_keypair_path(device_id);

    if !keypair_path.exists() {
        return Ok(false);
    }

    fs::remove_file(&keypair_path).map_err(|e| {
        error!("Failed to delete keypair for device {}: {}", device_id, e);
        RemoteClientError::KeypairStorage(format!("Failed to delete keypair: {}", e))
    })?;

    info!("Deleted static keypair for device: {}", device_id);
    Ok(true)
}

/// List all devices with stored static keypairs
pub fn list_devices() -> Result<Vec<String>, RemoteClientError> {
    let dir = get_keypair_directory();

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let entries = fs::read_dir(&dir).map_err(|e| {
        error!("Failed to list keypair directory: {}", e);
        RemoteClientError::KeypairStorage(format!("Failed to list devices: {}", e))
    })?;

    let devices: Vec<String> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") {
                Some(name.trim_end_matches(".json").to_string())
            } else {
                None
            }
        })
        .collect();

    Ok(devices)
}

/// Delete all static keypairs
///
/// WARNING: This will remove all device authentication keys.
/// Devices will need to re-pair after this operation.
pub fn clear_all_keypairs() -> Result<(), RemoteClientError> {
    let dir = get_keypair_directory();

    if !dir.exists() {
        return Ok(());
    }

    let entries = fs::read_dir(&dir).map_err(|e| {
        RemoteClientError::KeypairStorage(format!("Failed to read keypair directory: {}", e))
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            fs::remove_file(&path).ok();
        }
    }

    info!("Cleared all static keypairs");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_device_id() -> String {
        format!("test-device-{}", std::process::id())
    }

    #[test]
    fn test_generate_and_load_keypair() {
        let device_id = test_device_id();

        // Clean up first
        delete_static_keypair(&device_id).ok();

        // Generate
        let keypair = generate_static_keypair(&device_id).unwrap();
        assert_eq!(keypair.public_key().len(), 32);
        assert_eq!(keypair.secret_key().len(), 32);

        // Load
        let loaded = load_static_keypair(&device_id).unwrap().unwrap();
        assert_eq!(loaded.public_key(), keypair.public_key());
        assert_eq!(loaded.secret_key(), keypair.secret_key());

        // Clean up
        delete_static_keypair(&device_id).unwrap();
    }

    #[test]
    fn test_get_or_create() {
        let device_id = format!("{}-getorcreate", test_device_id());

        // Clean up first
        delete_static_keypair(&device_id).ok();

        // Should create
        let keypair1 = get_or_create_static_keypair(&device_id).unwrap();

        // Should load existing
        let keypair2 = get_or_create_static_keypair(&device_id).unwrap();
        assert_eq!(keypair1.public_key(), keypair2.public_key());

        // Clean up
        delete_static_keypair(&device_id).unwrap();
    }
}
