//! Versioned sealable payload for the open-organization-invite registration crossing.
//!
//! The payload structs live in their own file so both [`super::seal_open_org_invite_data`] and
//! [`super::unseal_open_org_invite_data`] can reference them. The
//! `generate_versioned_sealable!` invocation uses its optional visibility prefix to emit a
//! `pub(super)` enum so the sibling modules can see it.

use bitwarden_crypto::{
    generate_versioned_sealable,
    safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use serde::{Deserialize, Serialize};

/// Version 1 wire schema of the open-invite registration payload.
///
/// Once this shape ships it cannot be broken; if the fields change, add a new `V2` struct and
/// register both variants on [`RegistrationOpenOrgInviteData`].
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct RegistrationOpenOrgInviteDataV1 {
    pub(super) organization_id: String,
    pub(super) invite_link_code: String,
    pub(super) invite_key: String,
}

impl SealableData for RegistrationOpenOrgInviteDataV1 {}

generate_versioned_sealable!(
    pub(super) RegistrationOpenOrgInviteData,
    DataEnvelopeNamespace::RegistrationOpenOrgInviteData,
    [RegistrationOpenOrgInviteDataV1 => "1"]
);
