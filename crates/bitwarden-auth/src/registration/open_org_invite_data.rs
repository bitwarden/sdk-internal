//! Versioned sealable payload for the open-organization-invite registration crossing.
//!
//! The payload structs live in their own file so both [`super::seal_open_org_invite_data`] and
//! [`super::unseal_open_org_invite_data`] can reference them. The versioned enum matches what
//! `bitwarden_crypto::generate_versioned_sealable!` would emit, expanded manually so it can be
//! `pub(super)` and accessible across the sibling modules.

use bitwarden_crypto::safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData};
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

/// Adjacently tagged versioned wrapper. Serialization uses `{"version": "1", "content": {...}}`,
/// matching the shape `generate_versioned_sealable!` emits.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "version", content = "content")]
pub(super) enum RegistrationOpenOrgInviteData {
    #[serde(rename = "1")]
    V1(RegistrationOpenOrgInviteDataV1),
}

impl SealableVersionedData for RegistrationOpenOrgInviteData {
    const NAMESPACE: DataEnvelopeNamespace = DataEnvelopeNamespace::RegistrationOpenOrgInviteData;
}

impl From<RegistrationOpenOrgInviteDataV1> for RegistrationOpenOrgInviteData {
    fn from(value: RegistrationOpenOrgInviteDataV1) -> Self {
        Self::V1(value)
    }
}
