#![doc = include_str!("../README.md")]

bitwarden_commercial_marker::commercial_crate!();

mod policy;
mod rotation_config;
mod target_system;
#[cfg(test)]
mod test_support;

use bitwarden_crypto::{EncString, safe::DataEnvelope};
pub use policy::{
    GENERATOR_MAX_LENGTH, GENERATOR_MIN_LENGTH, PasswordPolicyError, SealedPasswordPolicy,
};
pub use rotation_config::{RotationConfigSealedV1, seal_rotation_config, unseal_rotation_config};
pub use target_system::{
    SealedTargetSystemKind, SealedTargetSystemMethod, TargetSystemSealedV1, seal_target_system,
    unseal_target_system,
};

/// Output of sealing. The server stores the two halves as separate fields so org-key rotation only
/// re-wraps `wrapped_key`.
#[derive(Debug, Clone)]
pub struct Sealed {
    /// Sent as `sealedData`.
    pub envelope: DataEnvelope,
    /// Sent as `wrappedKey`.
    pub wrapped_key: EncString,
}
