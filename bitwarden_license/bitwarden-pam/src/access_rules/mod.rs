//! PAM access rule CRUD operations.
//!
//! An *access rule* governs privileged access to a set of Bitwarden collections. Each rule bundles
//! together:
//!
//! - **Conditions** ([`AccessCondition`]) that must be satisfied before access is granted - for
//!   example requiring human approval or restricting access to an allow-list of CIDR ranges.
//! - **Lease parameters** controlling how long access lasts once granted: a default and maximum
//!   lease duration, whether a lease may be extended (and for how long), and whether a cipher may
//!   have at most one active lease at a time.
//! - The **collections** the rule governs.
//!
//! # Model layers
//!
//! - [`AccessRuleView`] - a decrypted view of a rule as returned by the server, including
//!   server-owned fields such as `id`, `organization_id`, and creation/revision timestamps.
//! - [`AccessRuleAddEditRequest`] - the input DTO for both creating and editing a rule. The same
//!   shape is used for create and edit because the server derives immutable fields from the URL
//!   (the organization and rule IDs) rather than the request body.
//! - [`AccessCondition`] - the condition wire contract, shared by both of the above.
//!
//! [`AccessRulesClient`] is the entry point for all operations and is obtained from the
//! [`PamClient`](crate::PamClient).
//!
//! # Conditions and forward compatibility
//!
//! [`AccessCondition`] mirrors the server's tagged wire format (`{"kind": "...", ...}`). The server
//! is the source of truth for which condition kinds exist; a given SDK version only models the
//! subset it understands. Any kind this SDK version doesn't recognize - or a recognized kind whose
//! payload doesn't match the expected shape - is captured verbatim by [`AccessCondition::Unknown`]
//! so that listing and enable/disable round-trips never destroy conditions the SDK can't interpret.
//! See [`AccessCondition`] for the full round-trip contract and its known limitations.
//!
//! # Validation
//!
//! [`AccessRuleAddEditRequest`]s are validated locally by
//! [`validate_request`](validate::validate_request) before being sent, so obviously-malformed
//! requests fail fast with a typed [`AccessRuleValidationError`] instead of a round trip. This
//! covers name length, lease-duration and extension consistency, the maximum condition count, and
//! CIDR syntax. Unknown condition kinds are deliberately *not* validated locally - the server
//! validates those. CIDR ranges are checked with [`is_valid_cidr`], which is intentionally stricter
//! than the server to avoid client/server disagreement about which network a rule matches.

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
