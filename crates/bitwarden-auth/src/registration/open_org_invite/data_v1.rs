//! Version 1 of the open-org-invite plaintext payload — the innermost thing sealed by the
//! [`bitwarden_crypto::safe::DataEnvelope`] in [`super::seal`]. Not to be confused with the sealed
//! opaque blob ([`super::SealedOpenOrgInviteData`]) or the outbound JSON
//! ([`super::SealedOpenOrgInvite`]); this file describes only the cleartext shape that gets
//! CBOR-encoded and encrypted.
//!
//! Once this shape ships it cannot be broken: any field change means adding a new `V2` struct
//! and registering both variants on the versioned enum in [`super`], so old sealed payloads
//! still unseal.

use bitwarden_crypto::safe::SealableData;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct RegistrationOpenOrgInviteDataV1 {
    pub(super) organization_id: String,
    pub(super) invite_link_code: String,
    pub(super) invite_key: String,
}

impl SealableData for RegistrationOpenOrgInviteDataV1 {}
