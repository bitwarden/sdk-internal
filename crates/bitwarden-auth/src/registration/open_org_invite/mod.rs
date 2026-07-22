//! Open-organization-invite registration crossing.
//!
//! The app seals an invite context on registration-start submit and unseals it on the accept
//! open-org-invite component after a successful registration-finish. This module owns the shared
//! wire schema (`wire_v1`), the seal path (`seal`), and the unseal path (`unseal`).

mod seal;
mod unseal;
mod wire_v1;

use bitwarden_crypto::{
    generate_versioned_sealable,
    safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
pub use seal::{OpenOrgInviteSealRequest, SealedOpenOrgInvite};
use serde::{Deserialize, Serialize};
use wire_v1::RegistrationOpenOrgInviteDataV1;

generate_versioned_sealable!(
    RegistrationOpenOrgInviteData,
    DataEnvelopeNamespace::RegistrationOpenOrgInviteData,
    [RegistrationOpenOrgInviteDataV1 => "1"]
);
