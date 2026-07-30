//! PAM access request operations.
//!
//! An *access request* is a member's ask to open a PAM-gated cipher. On the automatic (no human
//! approval) path the server auto-approves it, and the requester
//! [`activate`](AccessRequestsClient::activate)s the approved request to mint a short-lived
//! [`AccessLease`](crate::AccessLeaseView) over the cipher.
//!
//! [`AccessRequestsClient`] is obtained from the [`PamClient`](crate::PamClient) and covers reading
//! the caller's requests, activating an approved one, and cancelling a pending one.
//!
//! # Not yet exposed
//!
//! *Creating* a request (`POST /leases/ciphers/{id}`) and the per-cipher access-state / pre-check
//! reads depend on the `cipher_lease_api` binding, which is not yet generated into
//! `bitwarden-api-api`. Until it is, request creation stays on the clients' existing HTTP path and
//! per-cipher state can be derived from
//! [`LeasesClient::list_active`](crate::LeasesClient::list_active)
//! plus [`AccessRequestsClient::list_mine`].

mod client;
mod models;

pub use client::AccessRequestsClient;
pub use models::{AccessRequestStatus, AccessRequestView};
