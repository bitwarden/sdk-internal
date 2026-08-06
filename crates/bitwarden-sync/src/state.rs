//! Persisted state setting keys for the sync domain.

use bitwarden_state::register_setting_key;
use chrono::{DateTime, Utc};

register_setting_key!(
    /// Setting key for the timestamp of the last successful sync (or skip).
    pub(crate) const LAST_SYNC: DateTime<Utc> = "last_sync"
);
