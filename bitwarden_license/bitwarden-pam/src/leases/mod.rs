//! PAM access lease operations.
//!
//! An *access lease* is the short-lived grant that unlocks a gated cipher once a member activates
//! an approved access request.

mod client;
mod error;
mod models;

pub use client::LeasesClient;
pub use error::AccessLeaseError;
pub use models::{
    AccessLeaseExtensionRequest, AccessLeaseRevokeRequest, AccessLeaseStatus,
    AccessLeaseTermination, AccessLeaseView,
};
