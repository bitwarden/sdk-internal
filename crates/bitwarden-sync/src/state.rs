//! Persisted values for the sync domain.

use bitwarden_state::register_persisted_value;
use chrono::{DateTime, Utc};

register_persisted_value!(
    /// The timestamp of the last successful sync (or skip). Clients can manage it.
    pub LAST_SYNC: DateTime<Utc> = "last_sync"
);
