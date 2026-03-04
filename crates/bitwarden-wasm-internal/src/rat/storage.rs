//! In-memory implementations of `SessionStore` and `IdentityProvider` for WASM.
//!
//! These implementations keep all data in memory and provide serialization methods
//! so the JavaScript/TypeScript side can persist to `chrome.storage.local`.

use bw_rat_client::{
    IdentityFingerprint, IdentityKeyPair, MultiDeviceTransport, RemoteClientError,
};
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

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
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
