use std::sync::atomic::{AtomicBool, Ordering};

/// Key-management settings the host sets on a client after building it.
///
/// An application can run several clients for one user at once, e.g. a browser extension's
/// background and each of its open popups. Work that must happen once per application, such as
/// migrations, belongs to one of them.
pub(crate) struct CryptoSettings {
    /// Whether unlock runs local state migrations, such as the V1 to V2 PIN migration.
    perform_local_unlock_migrations: AtomicBool,
}

impl CryptoSettings {
    pub(crate) fn new() -> Self {
        Self {
            perform_local_unlock_migrations: AtomicBool::new(true),
        }
    }

    pub(crate) fn perform_local_unlock_migrations(&self) -> bool {
        self.perform_local_unlock_migrations.load(Ordering::Relaxed)
    }

    pub(crate) fn disable_local_unlock_migrations(&self) {
        self.perform_local_unlock_migrations
            .store(false, Ordering::Relaxed);
    }
}

impl Default for CryptoSettings {
    fn default() -> Self {
        Self::new()
    }
}
