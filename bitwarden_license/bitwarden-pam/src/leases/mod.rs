//! PAM access lease operations.
//!
//! An *access lease* is the short-lived, single-use grant that a member holds after an approved
//! [`AccessRequest`](crate::AccessRequestView) is activated. While the lease is
//! [`Active`](AccessLeaseStatus::Active) the member may open the cipher the request was for; when
//! it [`Expired`](AccessLeaseStatus::Expired) or is [`Revoked`](AccessLeaseStatus::Revoked) the
//! cipher re-locks.
//!
//! [`LeasesClient`] is obtained from the [`PamClient`](crate::PamClient) and covers reading the
//! caller's leases ([`list_active`](LeasesClient::list_active) /
//! [`list_mine`](LeasesClient::list_mine)), [`extend`](LeasesClient::extend)ing an active lease,
//! and [`end`](LeasesClient::end)ing one early. Leases are *minted* on the access-request side, by
//! [`AccessRequestsClient::activate`](crate::AccessRequestsClient::activate).

mod client;
mod error;
mod models;

pub use client::LeasesClient;
pub use error::AccessLeaseError;
pub use models::{
    AccessLeaseExtensionRequest, AccessLeaseRevokeRequest, AccessLeaseStatus,
    AccessLeaseTermination, AccessLeaseView,
};
