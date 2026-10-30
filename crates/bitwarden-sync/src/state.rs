//! Persisted values for the sync domain.

use bitwarden_state::register_persisted_value;
use chrono::{DateTime, Utc};

register_persisted_value!(
    /// Persisted value key for the timestamp of the last successful sync (or skip).
    pub(crate) LAST_SYNC: DateTime<Utc> = "last_sync"
);
