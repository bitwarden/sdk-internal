//! Open-organization-invite registration crossing.
//!
//! The app seals an invite context on registration-start submit and unseals it on the accept
//! open-org-invite component after a successful registration-finish. This module owns the
//! versioned plaintext payload (`data_v1`), the seal path (`seal`), and the unseal path
//! (`unseal`).

mod data_v1;
mod seal;
mod unseal;

use bitwarden_crypto::{
    generate_versioned_sealable,
    safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use data_v1::RegistrationOpenOrgInviteDataV1;
pub use seal::{
    OpenOrgInviteSealRequest, SealedEnvelopePair, SealedEnvelopePairError, SealedOpenOrgInvite,
};
use serde::{Deserialize, Serialize};

generate_versioned_sealable!(
    RegistrationOpenOrgInviteData,
    DataEnvelopeNamespace::RegistrationOpenOrgInviteData,
    [RegistrationOpenOrgInviteDataV1 => "1"]
);
