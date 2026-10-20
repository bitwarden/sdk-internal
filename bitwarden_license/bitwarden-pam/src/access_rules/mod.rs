//! PAM access rule CRUD operations.
//!
//! An *access rule* governs privileged access to a set of Bitwarden collections.

mod client;
mod conditions;
mod error;
mod models;
mod validate;

pub use client::AccessRulesClient;
pub use conditions::AccessCondition;
pub use error::AccessRuleError;
pub use models::{AccessRuleAddEditRequest, AccessRuleView};
pub use validate::{AccessRuleValidationError, is_valid_cidr};
