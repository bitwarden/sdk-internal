//! Open-organization-invite registration crossing.
//!
//! The app seals an invite context on registration-start submit and unseals it on the accept
//! open-org-invite component after a successful registration-finish. This module owns the
//! versioned plaintext payload (`data_v1`), the domain types and crypto operations
//! (`open_org_invite`), their wire encoding (`serialization`), and the FFI-facing client
//! methods (`client`).

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
