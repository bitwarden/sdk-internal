//! Version 1 wire schema of the open-invite registration payload.
//!
//! Once this shape ships it cannot be broken; if the fields change, add a new `V2` struct and
//! register both variants on the versioned enum in [`super`].

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
