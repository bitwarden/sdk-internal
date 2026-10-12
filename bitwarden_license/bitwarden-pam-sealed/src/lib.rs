#![doc = include_str!("../README.md")]

bitwarden_commercial_marker::commercial_crate!();

mod container;
mod policy;
mod rotation_config;
mod target_system;
#[cfg(test)]
mod test_support;

pub use container::SealedDataError;
pub use policy::{
    GENERATOR_MAX_LENGTH, GENERATOR_MIN_LENGTH, PasswordPolicyError, SealedPasswordPolicy,
};
pub use rotation_config::{RotationConfigSealedV1, seal_rotation_config, unseal_rotation_config};
pub use target_system::{
    SealedTargetSystemKind, SealedTargetSystemMethod, TargetSystemSealedV1, seal_target_system,
    unseal_target_system,
};
