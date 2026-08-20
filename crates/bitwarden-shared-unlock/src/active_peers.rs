//! Liveness tracking for the peers that sync to this one.

use std::{collections::HashMap, sync::Mutex, time::Duration};

use bitwarden_ipc::{Endpoint, Source};
use tracing::info;
use web_time::Instant;

/// A peer to sync to, together with the origin
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyncTarget {
    /// The address to send to.
    pub(crate) endpoint: Endpoint,
    /// The origin this peer was validated against. `Some` only for web peers.
    pub(crate) origin: Option<String>,
}

impl SyncTarget {
    /// The target for a validated incoming source, keeping the origin the source carried.
    pub(crate) fn from_source(source: &Source) -> Self {
        Self {
            endpoint: source.to_endpoint(),
            origin: match source {
                Source::Web { origin, .. } => Some(origin.clone()),
                _ => None,
            },
        }
    }

    /// A target with no origin, for a peer that was not reached through a validated source.
    pub(crate) fn without_origin(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            origin: None,
        }
    }
}

/// What is known about a peer that syncs to this one.
struct PeerRecord {
    /// When the peer was last heard from.
    last_seen: Instant,
    /// The origin validated when the peer was registered. `Some` only for web peers.
    origin: Option<String>,
}

/// Tracker for the active peers
#[derive(Default)]
pub(crate) struct ActivePeerTracker {
    peers: Mutex<HashMap<Endpoint, PeerRecord>>,
}

impl ActivePeerTracker {
    /// Records a peer as active, together with the origin it was validated against. Returns whether
    /// this is the first time it has been seen, which is what earns it an introductory reply.
    pub(crate) fn upsert(&self, target: &SyncTarget) -> bool {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let first_contact = !peers.contains_key(&target.endpoint);
        if first_contact {
            info!("Shared-Unlock peer connected {:?}", target.endpoint);
        }
        peers.insert(
            target.endpoint.clone(),
            PeerRecord {
                last_seen: Instant::now(),
                origin: target.origin.clone(),
            },
        );
        first_contact
    }

    pub(crate) fn targets(&self) -> Vec<SyncTarget> {
        self.peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(endpoint, record)| SyncTarget {
                endpoint: endpoint.clone(),
                origin: record.origin.clone(),
            })
            .collect()
    }

    /// Drops peers that have not been heard from within `stale_after`, so this peer stops syncing
    /// to clients that are no longer running.
    pub(crate) fn prune_stale(&self, stale_after: Duration) {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let now = Instant::now();
        peers.retain(|endpoint, record| {
            let alive = now.duration_since(record.last_seen) <= stale_after;
            if !alive {
                info!("Shared-Unlock peer {:?} disconnected", endpoint);
            }
            alive
        });
    }
}
