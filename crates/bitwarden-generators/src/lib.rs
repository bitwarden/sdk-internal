#![doc = include_str!("../README.md")]

mod generator_client;
mod username_forwarders;
pub use generator_client::{GeneratorClient, GeneratorClientsExt};
pub(crate) mod passphrase;
pub use passphrase::{
    MAXIMUM_PASSPHRASE_NUM_WORDS, MINIMUM_PASSPHRASE_NUM_WORDS, PassphraseError,
    PassphraseGeneratorRequest,
};
pub(crate) mod password;
pub use password::{
    MAXIMUM_MIN_CHAR_COUNT, MAXIMUM_PASSWORD_LENGTH, MINIMUM_MIN_CHAR_COUNT,
    MINIMUM_PASSWORD_LENGTH, PasswordError, PasswordGeneratorRequest,
};
pub(crate) mod username;
pub use username::{ForwarderServiceType, UsernameError, UsernameGeneratorRequest};
mod util;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
