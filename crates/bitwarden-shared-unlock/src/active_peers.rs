//! Liveness tracking for the peers that sync to this one.

use std::{collections::HashMap, sync::Mutex, time::Duration};

use bitwarden_ipc::Endpoint;
use tracing::info;
use web_time::Instant;

/// Tracker for the active peers
#[derive(Default)]
pub(crate) struct ActivePeerTracker {
    /// When each peer was last heard from.
    last_seen: Mutex<HashMap<Endpoint, Instant>>,
}

impl ActivePeerTracker {
    /// Records a peer as active. Returns whether this is the first time it has been seen, which is
    /// what earns it an introductory reply.
    pub(crate) fn upsert(&self, endpoint: Endpoint) -> bool {
        let mut last_seen = self
            .last_seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let first_contact = !last_seen.contains_key(&endpoint);
        if first_contact {
            info!("Shared-Unlock peer connected {:?}", endpoint);
        }
        last_seen.insert(endpoint, Instant::now());
        first_contact
    }

    pub(crate) fn endpoints(&self) -> Vec<Endpoint> {
        self.last_seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Drops peers that have not been heard from within `stale_after`, so this peer stops syncing
    /// to clients that are no longer running.
    pub(crate) fn prune_stale(&self, stale_after: Duration) {
        let mut last_seen = self
            .last_seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let now = Instant::now();
        last_seen.retain(|endpoint, last_seen_at| {
            let alive = now.duration_since(*last_seen_at) <= stale_after;
            if !alive {
                info!("Shared-Unlock peer {:?} disconnected", endpoint);
            }
            alive
        });
    }
}
