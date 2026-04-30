//! The registration module provides the registration client and related
//! type for registering new Bitwarden users via various cryptographic
//! mechanisms to establish their cryptographic state and register with
//! the Bitwarden server

mod post_keys_for_jit_password_registration;
mod post_keys_for_key_connector_registration;
mod post_keys_for_tde_registration;
mod post_keys_for_user_password_registration;
mod registration_client;

pub use post_keys_for_jit_password_registration::{
    JitMasterPasswordRegistrationRequest, JitMasterPasswordRegistrationResponse,
};
pub use post_keys_for_key_connector_registration::KeyConnectorRegistrationResult;
pub use post_keys_for_tde_registration::{TdeRegistrationRequest, TdeRegistrationResponse};
pub use post_keys_for_user_password_registration::{
    UserMasterPasswordRegistrationRequest, UserMasterPasswordRegistrationResponse,
};
pub use registration_client::{RegistrationClient, RegistrationError};
