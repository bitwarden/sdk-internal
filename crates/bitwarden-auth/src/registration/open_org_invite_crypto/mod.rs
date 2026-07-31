#![doc = include_str!("./README.md")]

mod client;
mod data_v1;
mod open_org_invite;
mod serialization;

use bitwarden_crypto::{
    generate_versioned_sealable,
    safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
pub use client::SealedOpenOrgInvite;
use data_v1::RegistrationOpenOrgInviteDataV1;
pub use open_org_invite::{OpenOrgInvite, SealedOpenOrgInviteData};
use serde::{Deserialize, Serialize};
pub use serialization::SealedOpenOrgInviteDataError;

generate_versioned_sealable!(
    RegistrationOpenOrgInviteData,
    DataEnvelopeNamespace::RegistrationOpenOrgInviteData,
    [RegistrationOpenOrgInviteDataV1 => "1"]
);
