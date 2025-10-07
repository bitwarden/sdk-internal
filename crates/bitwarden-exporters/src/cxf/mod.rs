//! Credential Exchange Format (CXF)
//!
//! This module implements support for the Credential Exchange standard as defined by the FIDO
//! Alliance.
//!
//! <https://fidoalliance.org/specifications-credential-exchange-specifications/>
mod error;
pub use error::CxfError;

mod export;
pub use export::Account;
pub(crate) use export::build_cxf;
mod import;
pub(crate) use import::parse_cxf;
mod api_key;
mod card;
mod editable_field;
mod identity;
mod login;
mod note;
mod ssh;
mod wifi;

#[cfg(test)]
mod tests;
