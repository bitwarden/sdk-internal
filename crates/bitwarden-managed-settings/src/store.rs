//! Process-global storage for the active [`ManagementProfile`].
//!
//! The prototype keeps the profile in a process-global `RwLock`. Production
//! swaps this for a host-implemented `ManagementProfileProvider` trait injected
//! at PM builder time (see `DESIGN.md`).
//!
//! The store is documented as global state for the prototype. It is acceptable
//! here because:
//!
//! 1. Per the trust model, the profile is forced by the OS at process scope —
//!    every `Client` in a given process is bound by the same admin policy.
//! 2. The injected-provider design in `DESIGN.md` keeps the public surface
//!    (`update_profile`, `is_managed`, `get`) identical, so swapping the
//!    storage strategy is a non-breaking change for clients.

use std::sync::{OnceLock, RwLock};

use crate::profile::ManagementProfile;

fn store() -> &'static RwLock<Option<ManagementProfile>> {
    static STORE: OnceLock<RwLock<Option<ManagementProfile>>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(None))
}

/// Replaces the active profile.
///
/// `None` clears the profile, restoring "no admin overrides" behavior.
pub(crate) fn set_profile(profile: Option<ManagementProfile>) {
    let mut guard = store().write().expect("managed-settings store poisoned");
    *guard = profile;
}

/// Returns a clone of the active profile, if any.
///
/// Returns `None` when no admin profile has been pushed into the SDK, which is
/// the default state on first start.
pub(crate) fn current_profile() -> Option<ManagementProfile> {
    store()
        .read()
        .expect("managed-settings store poisoned")
        .clone()
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    set_profile(None);
}
