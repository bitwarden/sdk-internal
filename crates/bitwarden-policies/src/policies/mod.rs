//! Concrete [`Policy`](crate::Policy) implementations, one per
//! [`PolicyType`](crate::PolicyType).
//!
//! Each policy lives in its own module alongside its `...PolicyData` struct (for
//! the policies that carry data) and any supporting enums. Future note: once the
//! policies crate is stable, each Policy implementation will be distributed to
//! the team that owns its domain.

mod activate_autofill;
mod automatic_app_log_in;
mod automatic_user_confirmation;
mod autotype_default_setting;
mod block_claimed_domain_account_creation;
mod disable_personal_vault_export;
mod disable_send;
mod fill_assist;
mod free_families_sponsorship;
mod master_password;
mod maximum_vault_timeout;
mod organization_data_ownership;
mod organization_user_notification;
mod password_generator;
mod remove_unlock_with_pin;
mod require_sso;
mod reset_password;
mod restricted_item_types;
mod send_controls;
mod send_options;
mod single_org;
mod two_factor_authentication;
mod uri_match_defaults;

pub use activate_autofill::*;
pub use automatic_app_log_in::*;
pub use automatic_user_confirmation::*;
pub use autotype_default_setting::*;
pub use block_claimed_domain_account_creation::*;
pub use disable_personal_vault_export::*;
pub use disable_send::*;
pub use fill_assist::*;
pub use free_families_sponsorship::*;
pub use master_password::*;
pub use maximum_vault_timeout::*;
pub use organization_data_ownership::*;
pub use organization_user_notification::*;
pub use password_generator::*;
pub use remove_unlock_with_pin::*;
pub use require_sso::*;
pub use reset_password::*;
pub use restricted_item_types::*;
pub use send_controls::*;
pub use send_options::*;
pub use single_org::*;
pub use two_factor_authentication::*;
pub use uri_match_defaults::*;
