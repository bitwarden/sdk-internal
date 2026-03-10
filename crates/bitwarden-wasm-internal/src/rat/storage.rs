//! In-memory implementations of `SessionStore` and `IdentityProvider` for WASM.
//!
//! These implementations keep all data in memory and provide serialization methods
//! so the JavaScript/TypeScript side can persist to `chrome.storage.local`.

use bw_noise_protocol::MultiDeviceTransport;
use bw_proxy_protocol::IdentityKeyPair;
use bw_rat_client::{IdentityFingerprint, RemoteClientError};
use serde::{Deserialize, Serialize};

/// A single cached session record.
#[derive(Clone, Serialize, Deserialize)]
struct SessionRecord {
    fingerprint: IdentityFingerprint,
    name: Option<String>,
    created_at: u64,
    last_connected: u64,
    transport_state: Option<Vec<u8>>,
}

#[cfg(target_arch = "wasm32")]
fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// In-memory session store with JSON serialization for browser persistence.
pub struct InMemorySessionStore {
    records: Vec<SessionRecord>,
}

impl InMemorySessionStore {
    /// Create an empty session store.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Deserialize from JSON (previously saved via `to_json`).
    pub fn from_json(data: &str) -> Result<Self, serde_json::Error> {
        let records: Vec<SessionRecord> = serde_json::from_str(data)?;
        Ok(Self { records })
    }

    /// Serialize the current state to JSON for browser persistence.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.records)
    }
}

impl bw_rat_client::SessionStore for InMemorySessionStore {
    fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        self.records.iter().any(|r| &r.fingerprint == fingerprint)
    }

    fn cache_session(&mut self, fingerprint: IdentityFingerprint) -> Result<(), RemoteClientError> {
        let now = now_secs();
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|r| r.fingerprint == fingerprint)
        {
            record.last_connected = now;
        } else {
            self.records.push(SessionRecord {
                fingerprint,
                name: None,
                created_at: now,
                last_connected: now,
                transport_state: None,
            });
        }
        Ok(())
    }

    fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        self.records.retain(|r| &r.fingerprint != fingerprint);
        Ok(())
    }

    fn clear(&mut self) -> Result<(), RemoteClientError> {
        self.records.clear();
        Ok(())
    }

    fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
        self.records
            .iter()
            .map(|r| {
                (
                    r.fingerprint,
                    r.name.clone(),
                    r.created_at,
                    r.last_connected,
                )
            })
            .collect()
    }

    fn set_session_name(
        &mut self,
        fingerprint: &IdentityFingerprint,
        name: String,
    ) -> Result<(), RemoteClientError> {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|r| &r.fingerprint == fingerprint)
        {
            record.name = Some(name);
            Ok(())
        } else {
            Err(RemoteClientError::SessionNotFound)
        }
    }

    fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|r| &r.fingerprint == fingerprint)
        {
            record.last_connected = now_secs();
            Ok(())
        } else {
            Err(RemoteClientError::SessionNotFound)
        }
    }

    fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), RemoteClientError> {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|r| &r.fingerprint == fingerprint)
        {
            let serialized = transport_state
                .save_state()
                .map_err(|e| RemoteClientError::SessionCache(e.to_string()))?;
            record.transport_state = Some(serialized);
            Ok(())
        } else {
            Err(RemoteClientError::SessionNotFound)
        }
    }

    fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, RemoteClientError> {
        if let Some(record) = self.records.iter().find(|r| &r.fingerprint == fingerprint) {
            match &record.transport_state {
                Some(data) => {
                    let transport = MultiDeviceTransport::restore_state(data)
                        .map_err(|e| RemoteClientError::SessionCache(e.to_string()))?;
                    Ok(Some(transport))
                }
                None => Ok(None),
            }
        } else {
            Err(RemoteClientError::SessionNotFound)
        }
    }
}

/// In-memory identity provider with serialization for browser persistence.
pub struct InMemoryIdentityProvider {
    keypair: IdentityKeyPair,
}

impl InMemoryIdentityProvider {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        Self {
            keypair: IdentityKeyPair::generate(),
        }
    }

    /// Load from COSE-encoded bytes (previously saved via `to_bytes`).
    /// Load from COSE-encoded bytes.
    ///
    /// Returns `None` if the bytes are invalid.
    pub fn from_bytes(cose_bytes: &[u8]) -> Result<Self, String> {
        let keypair = IdentityKeyPair::from_cose(cose_bytes).map_err(|e| e.to_string())?;
        Ok(Self { keypair })
    }

    /// Serialize the identity to COSE-encoded bytes for browser persistence.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.keypair.to_cose()
    }
}

impl bw_rat_client::IdentityProvider for InMemoryIdentityProvider {
    fn identity(&self) -> &IdentityKeyPair {
        &self.keypair
    }
}

#[cfg(test)]
mod tests {
    use bw_rat_client::SessionStore;

    use super::*;

    fn test_fingerprint(byte: u8) -> IdentityFingerprint {
        IdentityFingerprint([byte; 32])
    }

    // --- InMemorySessionStore ---

    #[test]
    fn empty_store_has_no_sessions() {
        let store = InMemorySessionStore::new();
        assert!(!store.has_session(&test_fingerprint(0x01)));
        assert!(store.list_sessions().is_empty());
    }

    #[test]
    fn cache_session_makes_it_findable() {
        let mut store = InMemorySessionStore::new();
        let fp = test_fingerprint(0xAB);
        store.cache_session(fp).unwrap();

        assert!(store.has_session(&fp));
        let sessions = store.list_sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].0, fp);
        assert!(sessions[0].1.is_none()); // no name
        assert!(sessions[0].2 > 0); // created_at
        assert!(sessions[0].3 > 0); // last_connected
    }

    #[test]
    fn cache_session_twice_updates_last_connected() {
        let mut store = InMemorySessionStore::new();
        let fp = test_fingerprint(0x01);
        store.cache_session(fp).unwrap();
        let first = store.list_sessions()[0].3;

        store.cache_session(fp).unwrap();
        let second = store.list_sessions()[0].3;

        // Should still be 1 session, last_connected >= first
        assert_eq!(store.list_sessions().len(), 1);
        assert!(second >= first);
    }

    #[test]
    fn remove_session_deletes_it() {
        let mut store = InMemorySessionStore::new();
        let fp = test_fingerprint(0x01);
        store.cache_session(fp).unwrap();
        assert!(store.has_session(&fp));

        store.remove_session(&fp).unwrap();
        assert!(!store.has_session(&fp));
        assert!(store.list_sessions().is_empty());
    }

    #[test]
    fn remove_nonexistent_session_is_ok() {
        let mut store = InMemorySessionStore::new();
        store.remove_session(&test_fingerprint(0xFF)).unwrap();
    }

    #[test]
    fn clear_removes_all_sessions() {
        let mut store = InMemorySessionStore::new();
        store.cache_session(test_fingerprint(0x01)).unwrap();
        store.cache_session(test_fingerprint(0x02)).unwrap();
        assert_eq!(store.list_sessions().len(), 2);

        store.clear().unwrap();
        assert!(store.list_sessions().is_empty());
    }

    #[test]
    fn set_session_name_on_existing() {
        let mut store = InMemorySessionStore::new();
        let fp = test_fingerprint(0x01);
        store.cache_session(fp).unwrap();

        store.set_session_name(&fp, "My Device".into()).unwrap();
        let sessions = store.list_sessions();
        assert_eq!(sessions[0].1.as_deref(), Some("My Device"));
    }

    #[test]
    fn set_session_name_on_missing_returns_error() {
        let mut store = InMemorySessionStore::new();
        let result = store.set_session_name(&test_fingerprint(0xFF), "name".into());
        assert!(result.is_err());
    }

    #[test]
    fn update_last_connected_on_missing_returns_error() {
        let mut store = InMemorySessionStore::new();
        let result = store.update_last_connected(&test_fingerprint(0xFF));
        assert!(result.is_err());
    }

    #[test]
    fn load_transport_state_missing_session_returns_error() {
        let store = InMemorySessionStore::new();
        let result = store.load_transport_state(&test_fingerprint(0xFF));
        assert!(result.is_err());
    }

    #[test]
    fn load_transport_state_no_state_returns_none() {
        let mut store = InMemorySessionStore::new();
        let fp = test_fingerprint(0x01);
        store.cache_session(fp).unwrap();

        let state = store.load_transport_state(&fp).unwrap();
        assert!(state.is_none());
    }

    #[test]
    fn json_roundtrip_empty_store() {
        let store = InMemorySessionStore::new();
        let json = store.to_json().unwrap();
        let restored = InMemorySessionStore::from_json(&json).unwrap();
        assert!(restored.list_sessions().is_empty());
    }

    #[test]
    fn json_roundtrip_with_sessions() {
        let mut store = InMemorySessionStore::new();
        let fp1 = test_fingerprint(0x01);
        let fp2 = test_fingerprint(0x02);
        store.cache_session(fp1).unwrap();
        store.cache_session(fp2).unwrap();
        store.set_session_name(&fp1, "Device A".into()).unwrap();

        let json = store.to_json().unwrap();
        let restored = InMemorySessionStore::from_json(&json).unwrap();

        assert_eq!(restored.list_sessions().len(), 2);
        assert!(restored.has_session(&fp1));
        assert!(restored.has_session(&fp2));

        let sessions = restored.list_sessions();
        let device_a = sessions.iter().find(|s| s.0 == fp1).unwrap();
        assert_eq!(device_a.1.as_deref(), Some("Device A"));
    }

    #[test]
    fn from_json_invalid_returns_error() {
        let result = InMemorySessionStore::from_json("not valid json{{{");
        assert!(result.is_err());
    }

    #[test]
    fn multiple_sessions_independent() {
        let mut store = InMemorySessionStore::new();
        let fp1 = test_fingerprint(0x01);
        let fp2 = test_fingerprint(0x02);
        store.cache_session(fp1).unwrap();
        store.cache_session(fp2).unwrap();

        store.remove_session(&fp1).unwrap();
        assert!(!store.has_session(&fp1));
        assert!(store.has_session(&fp2));
        assert_eq!(store.list_sessions().len(), 1);
    }

    // --- InMemoryIdentityProvider ---

    #[test]
    fn generate_identity_produces_valid_keypair() {
        let provider = InMemoryIdentityProvider::generate();
        let bytes = provider.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn identity_cose_roundtrip() {
        let provider = InMemoryIdentityProvider::generate();
        let bytes = provider.to_bytes();

        let restored = InMemoryIdentityProvider::from_bytes(&bytes).unwrap();
        let restored_bytes = restored.to_bytes();

        assert_eq!(bytes, restored_bytes);
    }

    #[test]
    fn identity_from_invalid_bytes_returns_error() {
        let result = InMemoryIdentityProvider::from_bytes(&[0xFF, 0x00, 0x42]);
        assert!(result.is_err());
    }

    #[test]
    fn identity_from_empty_bytes_returns_error() {
        let result = InMemoryIdentityProvider::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn identity_provider_trait_returns_keypair() {
        use bw_rat_client::IdentityProvider;

        let provider = InMemoryIdentityProvider::generate();
        let identity = provider.identity();
        // Verify we can get the public identity and fingerprint
        let public = identity.identity();
        let fp = public.fingerprint();
        assert_ne!(fp.0, [0u8; 32]); // fingerprint should be non-zero
    }

    #[test]
    fn two_generated_identities_differ() {
        let a = InMemoryIdentityProvider::generate();
        let b = InMemoryIdentityProvider::generate();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }
}
