//! The cross-crate seam that lets typed SDK requests apply admin overrides.
//!
//! Feature crates (e.g. `bitwarden-generators`) implement
//! [`ApplyManagedOverride`] for their `*Request` structs. The generator client
//! consults the active profile before generating, runs `apply_managed_override`,
//! and then validates as usual. This keeps managed-settings resolution out of
//! the generator's core algorithm.

use bitwarden_managed_settings_types::ManagementProfile;

/// Apply the managed-settings overrides from `profile` to `self`.
///
/// Implementors map well-known dotted keys (e.g. `generator.password.length`)
/// onto the corresponding fields, clamped to whatever per-field bounds the
/// implementor enforces. The trait is intentionally infallible — bad values in
/// the profile are clamped or ignored, never propagated as errors. A bad
/// profile must not stop the user from generating a password.
pub trait ApplyManagedOverride {
    /// Returns `self` with every managed key applied.
    fn apply_managed_override(self, profile: &ManagementProfile) -> Self;
}
