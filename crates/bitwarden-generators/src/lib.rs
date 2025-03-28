#![doc = include_str!("../README.md")]

mod generator_client;
mod username_forwarders;
pub use generator_client::{GeneratorClient, GeneratorClientsExt};
pub(crate) mod passphrase;
pub use passphrase::{PassphraseError, PassphraseGeneratorRequest};
pub(crate) mod password;
pub use password::{PasswordError, PasswordGeneratorRequest};
pub(crate) mod username;
pub use username::{ForwarderServiceType, UsernameError, UsernameGeneratorRequest};
mod util;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
