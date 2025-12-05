//! Session cache for persisting PSK across connections
//!
//! Stores derived PSKs so that subsequent connections don't require
//! re-entering the pairing code.

use std::{fs, path::PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::error::RemoteClientError;

/// A cached session entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSession {
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    /// Base64-encoded PSK
    session_key: String,
    created_at: u64,
}

/// Session cache for storing PSKs
#[derive(Debug)]
pub struct SessionCache {
    cache_file_path: PathBuf,
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SessionCache {
    /// Create a new session cache
    ///
    /// # Arguments
    /// * `cache_file_name` - Optional custom cache file name. Defaults to `.noise-sessions.json`
    pub fn new(cache_file_name: Option<&str>) -> Self {
        let file_name = cache_file_name.unwrap_or(".noise-sessions.json");
        let cache_file_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(file_name);

        Self { cache_file_path }
    }

    /// Load a cached PSK for a specific username and optional client ID
    ///
    /// # Arguments
    /// * `username` - The username to look up
    /// * `client_id` - Optional client ID to match
    ///
    /// # Returns
    /// The cached PSK if found, or None
    pub fn load(&self, username: &str, client_id: Option<&str>) -> Option<Vec<u8>> {
        let sessions = self.load_sessions().ok()?;

        let session = sessions.iter().find(|s| {
            s.username == username && (client_id.is_none() || s.client_id.as_deref() == client_id)
        })?;

        let client_info = client_id
            .map(|c| format!(" (client: {})", c))
            .unwrap_or_default();
        info!(
            "Found cached session for {}{} (created {})",
            username, client_info, session.created_at
        );

        STANDARD.decode(&session.session_key).ok()
    }

    /// Save a PSK for a specific username and optional client ID
    ///
    /// # Arguments
    /// * `username` - The username to save for
    /// * `psk` - The PSK bytes to cache
    /// * `client_id` - Optional client ID
    pub fn save(
        &self,
        username: &str,
        psk: &[u8],
        client_id: Option<&str>,
    ) -> Result<(), RemoteClientError> {
        let mut sessions = self.load_sessions().unwrap_or_default();

        // Remove any existing session for this username and client_id
        sessions.retain(|s| !(s.username == username && s.client_id.as_deref() == client_id));

        // Add new session
        let new_session = CachedSession {
            username: username.to_string(),
            client_id: client_id.map(String::from),
            session_key: STANDARD.encode(psk),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        sessions.push(new_session);

        self.save_sessions(&sessions)?;

        let client_info = client_id
            .map(|c| format!(" (client: {})", c))
            .unwrap_or_default();
        info!("Cached session for {}{}", username, client_info);

        Ok(())
    }

    /// Check if a cached session exists for a username and optional client ID
    pub fn has(&self, username: &str, client_id: Option<&str>) -> bool {
        self.load(username, client_id).is_some()
    }

    /// Clear all cached sessions
    pub fn clear_all(&self) -> Result<(), RemoteClientError> {
        if self.cache_file_path.exists() {
            fs::remove_file(&self.cache_file_path).map_err(|e| {
                RemoteClientError::SessionCache(format!("Failed to clear cache: {}", e))
            })?;
            info!("Cleared all cached sessions");
        } else {
            debug!("No cached sessions to clear");
        }
        Ok(())
    }

    /// Clear a specific user's cached session
    pub fn clear(&self, username: &str, client_id: Option<&str>) -> Result<(), RemoteClientError> {
        let mut sessions = self.load_sessions().unwrap_or_default();
        let original_len = sessions.len();

        sessions.retain(|s| {
            !(s.username == username
                && (client_id.is_none() || s.client_id.as_deref() == client_id))
        });

        if sessions.len() == original_len {
            let client_info = client_id
                .map(|c| format!(" (client: {})", c))
                .unwrap_or_default();
            debug!("No cached session found for {}{}", username, client_info);
            return Ok(());
        }

        if sessions.is_empty() {
            fs::remove_file(&self.cache_file_path).ok();
        } else {
            self.save_sessions(&sessions)?;
        }

        let client_info = client_id
            .map(|c| format!(" (client: {})", c))
            .unwrap_or_default();
        info!("Cleared cached session for {}{}", username, client_info);

        Ok(())
    }

    /// List all cached sessions (for management purposes)
    pub fn list(&self) -> Vec<SessionInfo> {
        self.load_sessions()
            .unwrap_or_default()
            .into_iter()
            .map(|s| SessionInfo {
                username: s.username,
                client_id: s.client_id,
                created_at: s.created_at,
            })
            .collect()
    }

    fn load_sessions(&self) -> Result<Vec<CachedSession>, RemoteClientError> {
        if !self.cache_file_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&self.cache_file_path).map_err(|e| {
            error!("Failed to read session cache: {}", e);
            RemoteClientError::SessionCache(format!("Failed to read cache: {}", e))
        })?;

        serde_json::from_str(&content).map_err(|e| {
            error!("Failed to parse session cache: {}", e);
            RemoteClientError::SessionCache(format!("Failed to parse cache: {}", e))
        })
    }

    fn save_sessions(&self, sessions: &[CachedSession]) -> Result<(), RemoteClientError> {
        let content = serde_json::to_string_pretty(sessions)?;

        fs::write(&self.cache_file_path, content).map_err(|e| {
            error!("Failed to write session cache: {}", e);
            RemoteClientError::SessionCache(format!("Failed to write cache: {}", e))
        })?;

        Ok(())
    }
}

/// Information about a cached session (without sensitive data)
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Username for the session
    pub username: String,
    /// Client ID if specified
    pub client_id: Option<String>,
    /// Unix timestamp when session was created
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    fn temp_cache(test_name: &str) -> SessionCache {
        let temp_file = env::temp_dir().join(format!(
            "test-noise-sessions-{}-{}.json",
            std::process::id(),
            test_name
        ));
        // Clean up any existing file to ensure test isolation
        let _ = std::fs::remove_file(&temp_file);
        SessionCache {
            cache_file_path: temp_file,
        }
    }

    #[test]
    fn test_save_and_load() {
        let cache = temp_cache("save_and_load");
        let psk = vec![1u8; 32];

        cache.save("testuser", &psk, None).unwrap();

        let loaded = cache.load("testuser", None);
        assert_eq!(loaded, Some(psk));

        cache.clear_all().unwrap();
    }

    #[test]
    fn test_save_with_client_id() {
        let cache = temp_cache("save_with_client_id");
        let psk1 = vec![1u8; 32];
        let psk2 = vec![2u8; 32];

        cache.save("testuser", &psk1, Some("device1")).unwrap();
        cache.save("testuser", &psk2, Some("device2")).unwrap();

        assert_eq!(cache.load("testuser", Some("device1")), Some(psk1));
        assert_eq!(cache.load("testuser", Some("device2")), Some(psk2));

        cache.clear_all().unwrap();
    }

    #[test]
    fn test_clear() {
        let cache = temp_cache("clear");
        let psk = vec![1u8; 32];

        cache.save("testuser", &psk, None).unwrap();
        assert!(cache.has("testuser", None));

        cache.clear("testuser", None).unwrap();
        assert!(!cache.has("testuser", None));

        cache.clear_all().unwrap();
    }
}
