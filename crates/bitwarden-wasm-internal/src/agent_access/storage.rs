//! Connection storage implementations for WASM.
//!
//! Provides `RepositoryConnectionStore` backed by a `Repository` for auto-persistence
//! via the JS side. For tests, use `ap_client::MemoryConnectionStore`.

use std::sync::Arc;

use ap_client::{
    ClientError, ConnectionInfo, ConnectionStore, ConnectionUpdate, IdentityFingerprint, PskEntry,
    PskStore,
};
use ap_noise::{MultiDeviceTransport, Psk};
use ap_proxy_protocol::IdentityKeyPair;
use async_trait::async_trait;
use bitwarden_state::repository::{Repository, RepositoryError};
use serde::{Deserialize, Serialize};

use super::proxy::fingerprint_to_hex;

/// A single cached connection record, stored in a Repository keyed by hex fingerprint.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionRecord {
    pub fingerprint: IdentityFingerprint,
    pub name: Option<String>,
    pub cached_at: u64,
    pub last_connected_at: u64,
    pub transport_state: Option<Vec<u8>>,
}

// Register ConnectionRecord as a repository item with String keys (hex fingerprint).
bitwarden_state::register_repository_item!(String => ConnectionRecord, "ConnectionRecord");

fn repo_err(e: RepositoryError) -> ClientError {
    ClientError::ConnectionCache(e.to_string())
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

// ---------------------------------------------------------------------------
// Conversion: ConnectionInfo ↔ ConnectionRecord
// ---------------------------------------------------------------------------

fn connection_info_to_record(info: ConnectionInfo) -> Result<ConnectionRecord, ClientError> {
    let transport_state = match info.transport_state {
        Some(transport) => {
            let serialized = transport
                .save_state()
                .map_err(|e| ClientError::ConnectionCache(e.to_string()))?;
            Some(serialized)
        }
        None => None,
    };
    Ok(ConnectionRecord {
        fingerprint: info.fingerprint,
        name: info.name,
        cached_at: info.cached_at,
        last_connected_at: info.last_connected_at,
        transport_state,
    })
}

fn record_to_connection_info(record: ConnectionRecord) -> Result<ConnectionInfo, ClientError> {
    let transport_state = match record.transport_state {
        Some(data) => {
            let transport = MultiDeviceTransport::restore_state(&data)
                .map_err(|e| ClientError::ConnectionCache(e.to_string()))?;
            Some(transport)
        }
        None => None,
    };
    Ok(ConnectionInfo {
        fingerprint: record.fingerprint,
        name: record.name,
        cached_at: record.cached_at,
        last_connected_at: record.last_connected_at,
        transport_state,
    })
}

// ---------------------------------------------------------------------------
// RepositoryConnectionStore — auto-persisted via JS Repository
// ---------------------------------------------------------------------------

/// Connection store backed by a `Repository<ConnectionRecord>`.
///
/// Every mutation is immediately persisted through the Repository, so the JS
/// side sees changes without any manual `persistState()` calls.
pub struct RepositoryConnectionStore {
    repo: Arc<dyn Repository<ConnectionRecord>>,
}

impl RepositoryConnectionStore {
    pub fn new(repo: Arc<dyn Repository<ConnectionRecord>>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl ConnectionStore for RepositoryConnectionStore {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        let key = fingerprint_to_hex(fingerprint);
        match self.repo.get(key).await {
            Ok(Some(record)) => record_to_connection_info(record).ok(),
            _ => None,
        }
    }

    async fn save(&mut self, connection: ConnectionInfo) -> Result<(), ClientError> {
        let key = fingerprint_to_hex(&connection.fingerprint);
        let record = connection_info_to_record(connection)?;
        self.repo.set(key, record).await.map_err(repo_err)
    }

    async fn update(&mut self, update: ConnectionUpdate) -> Result<(), ClientError> {
        let key = fingerprint_to_hex(&update.fingerprint);
        let mut record = self
            .repo
            .get(key.clone())
            .await
            .map_err(repo_err)?
            .ok_or(ClientError::ConnectionNotFound)?;
        record.last_connected_at = update.last_connected_at;
        self.repo.set(key, record).await.map_err(repo_err)
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.repo
            .list()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| record_to_connection_info(r).ok())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// PskRecord + RepositoryPskStore — reusable PSK persistence via JS Repository
// ---------------------------------------------------------------------------

/// A stored reusable PSK record, persisted via a JS Repository keyed by `psk_id`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PskRecord {
    pub psk_id: String,
    pub psk_hex: String,
    pub name: Option<String>,
    pub created_at: u64,
}

bitwarden_state::register_repository_item!(String => PskRecord, "PskRecord");

fn psk_entry_to_record(entry: &PskEntry) -> PskRecord {
    PskRecord {
        psk_id: entry.psk_id.clone(),
        psk_hex: entry.psk.to_hex(),
        name: entry.name.clone(),
        created_at: entry.created_at,
    }
}

fn record_to_psk_entry(record: PskRecord) -> Result<PskEntry, ClientError> {
    let psk =
        Psk::from_hex(&record.psk_hex).map_err(|e| ClientError::ConnectionCache(e.to_string()))?;
    Ok(PskEntry {
        psk_id: record.psk_id,
        psk,
        name: record.name,
        created_at: record.created_at,
    })
}

/// PSK store backed by a `Repository<PskRecord>`.
pub struct RepositoryPskStore {
    repo: Arc<dyn Repository<PskRecord>>,
}

impl RepositoryPskStore {
    pub fn new(repo: Arc<dyn Repository<PskRecord>>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl PskStore for RepositoryPskStore {
    async fn get(&self, psk_id: &String) -> Option<PskEntry> {
        match self.repo.get(psk_id.clone()).await {
            Ok(Some(record)) => record_to_psk_entry(record).ok(),
            _ => None,
        }
    }

    async fn save(&mut self, entry: PskEntry) -> Result<(), ClientError> {
        let key = entry.psk_id.clone();
        let record = psk_entry_to_record(&entry);
        self.repo.set(key, record).await.map_err(repo_err)
    }

    async fn remove(&mut self, psk_id: &String) -> Result<(), ClientError> {
        self.repo.remove(psk_id.clone()).await.map_err(repo_err)
    }

    async fn list(&self) -> Vec<PskEntry> {
        self.repo
            .list()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| record_to_psk_entry(r).ok())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// InMemoryIdentityProvider — kept for tests and CLI use
// ---------------------------------------------------------------------------

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

    /// Load from COSE-encoded bytes.
    ///
    /// Returns an error if the bytes are invalid.
    pub fn from_bytes(cose_bytes: &[u8]) -> Result<Self, String> {
        let keypair = IdentityKeyPair::from_cose(cose_bytes).map_err(|e| e.to_string())?;
        Ok(Self { keypair })
    }

    /// Serialize the identity to COSE-encoded bytes for browser persistence.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.keypair.to_cose()
    }
}

#[async_trait]
impl ap_client::IdentityProvider for InMemoryIdentityProvider {
    async fn identity(&self) -> IdentityKeyPair {
        self.keypair.clone()
    }
}

/// Generate a new random agent-access identity keypair, returned as COSE-encoded bytes.
///
/// This is a standalone utility for the JS identity service to call when creating
/// a new identity for vault storage.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn generate_agent_identity() -> Vec<u8> {
    InMemoryIdentityProvider::generate().to_bytes()
}

#[cfg(test)]
mod tests {
    use ap_client::{ConnectionInfo, ConnectionStore, ConnectionUpdate, MemoryConnectionStore};

    use super::*;

    fn test_fingerprint(byte: u8) -> IdentityFingerprint {
        IdentityFingerprint([byte; 32])
    }

    fn make_connection_info(byte: u8) -> ConnectionInfo {
        ConnectionInfo {
            fingerprint: test_fingerprint(byte),
            name: None,
            cached_at: now_secs(),
            last_connected_at: now_secs(),
            transport_state: None,
        }
    }

    // --- MemoryConnectionStore (from library) ---

    #[tokio::test]
    async fn empty_store_has_no_connections() {
        let store = MemoryConnectionStore::new();
        assert!(store.get(&test_fingerprint(0x01)).await.is_none());
        assert!(store.list().await.is_empty());
    }

    #[tokio::test]
    async fn save_makes_connection_findable() {
        let mut store = MemoryConnectionStore::new();
        let fp = test_fingerprint(0xAB);
        store.save(make_connection_info(0xAB)).await.unwrap();

        let retrieved = store.get(&fp).await;
        assert!(retrieved.is_some());
        let conn = retrieved.unwrap();
        assert_eq!(conn.fingerprint, fp);
        assert!(conn.name.is_none());
        assert!(conn.cached_at > 0);
        assert!(conn.last_connected_at > 0);
    }

    #[tokio::test]
    async fn save_overwrites_existing() {
        let mut store = MemoryConnectionStore::new();
        store.save(make_connection_info(0x01)).await.unwrap();

        let mut updated = make_connection_info(0x01);
        updated.name = Some("Updated".to_string());
        store.save(updated).await.unwrap();

        let connections = store.list().await;
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].name.as_deref(), Some("Updated"));
    }

    #[tokio::test]
    async fn update_changes_last_connected() {
        let mut store = MemoryConnectionStore::new();
        let fp = test_fingerprint(0x01);
        store.save(make_connection_info(0x01)).await.unwrap();

        let update = ConnectionUpdate {
            fingerprint: fp,
            last_connected_at: 9999,
        };
        store.update(update).await.unwrap();

        let conn = store.get(&fp).await.unwrap();
        assert_eq!(conn.last_connected_at, 9999);
    }

    #[tokio::test]
    async fn update_nonexistent_returns_error() {
        let mut store = MemoryConnectionStore::new();
        let update = ConnectionUpdate {
            fingerprint: test_fingerprint(0xFF),
            last_connected_at: 9999,
        };
        assert!(store.update(update).await.is_err());
    }

    #[tokio::test]
    async fn list_returns_all_connections() {
        let mut store = MemoryConnectionStore::new();
        store.save(make_connection_info(0x01)).await.unwrap();
        store.save(make_connection_info(0x02)).await.unwrap();
        assert_eq!(store.list().await.len(), 2);
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

    #[tokio::test]
    async fn identity_provider_trait_returns_keypair() {
        use ap_client::IdentityProvider;

        let provider = InMemoryIdentityProvider::generate();
        let identity = provider.identity().await;
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

    // --- MemoryPskStore (from library) ---

    fn make_psk_entry(name: Option<&str>) -> PskEntry {
        let psk = Psk::generate();
        PskEntry {
            psk_id: psk.id(),
            psk,
            name: name.map(|s| s.to_string()),
            created_at: now_secs(),
        }
    }

    #[tokio::test]
    async fn empty_psk_store_has_no_entries() {
        let store = ap_client::MemoryPskStore::new();
        assert!(store.list().await.is_empty());
    }

    #[tokio::test]
    async fn psk_save_makes_entry_findable() {
        let mut store = ap_client::MemoryPskStore::new();
        let entry = make_psk_entry(Some("test"));
        let psk_id = entry.psk_id.clone();
        store.save(entry).await.unwrap();

        let retrieved = store.get(&psk_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name.as_deref(), Some("test"));
    }

    #[tokio::test]
    async fn psk_remove_deletes_entry() {
        let mut store = ap_client::MemoryPskStore::new();
        let entry = make_psk_entry(None);
        let psk_id = entry.psk_id.clone();
        store.save(entry).await.unwrap();
        assert_eq!(store.list().await.len(), 1);

        store.remove(&psk_id).await.unwrap();
        assert!(store.get(&psk_id).await.is_none());
        assert!(store.list().await.is_empty());
    }

    #[test]
    fn psk_record_roundtrip() {
        let entry = make_psk_entry(Some("roundtrip"));
        let record = psk_entry_to_record(&entry);
        let restored = record_to_psk_entry(record).unwrap();
        assert_eq!(restored.psk_id, entry.psk_id);
        assert_eq!(restored.name.as_deref(), Some("roundtrip"));
        assert_eq!(restored.psk.to_hex(), entry.psk.to_hex());
    }
}
