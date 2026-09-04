//! FFI-facing seal/unseal. The [`RegistrationClient`] methods are thin wrappers over
//! [`SealedOpenOrgInviteData::seal`] / [`SealedOpenOrgInviteData::unseal`];
//! [`SealedOpenOrgInvite`] bundles both halves of the seal output as one WASM return type.

use bitwarden_crypto::safe::HighEntropySecret;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{OpenOrgInvite, SealedOpenOrgInviteData};
use crate::registration::registration_client::{RegistrationClient, RegistrationError};

/// Sealed open-organization-invite payload. Produced by
/// [`RegistrationClient::seal_open_org_invite_data`] and consumed by
/// [`RegistrationClient::unseal_open_org_invite_data`]. Both fields are required to unseal;
/// neither half is useful on its own.
#[bitwarden_ffi::wasm_record]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SealedOpenOrgInvite {
    /// URL-safe opaque payload; place on the verification-email link.
    pub sealed_data: SealedOpenOrgInviteData,
    /// Paired secret; keep client-side (e.g. `localStorage`) and never send to the server.
    pub high_entropy_secret: HighEntropySecret,
}

#[bitwarden_ffi::wasm_export]
impl RegistrationClient {
    /// Seals an [`OpenOrgInvite`] into a [`SealedOpenOrgInvite`]. The returned
    /// `sealed_data` is safe to place on the verification-email link; the returned
    /// `high_entropy_secret` must stay client-side.
    pub fn seal_open_org_invite_data(
        &self,
        input: OpenOrgInvite,
    ) -> Result<SealedOpenOrgInvite, RegistrationError> {
        let (sealed_data, high_entropy_secret) = SealedOpenOrgInviteData::seal(input)?;
        Ok(SealedOpenOrgInvite {
            sealed_data,
            high_entropy_secret,
        })
    }

    /// Unseals a [`SealedOpenOrgInvite`] back into an [`OpenOrgInvite`]. Returns
    /// [`RegistrationError::Crypto`] if the paired secret does not match the sealed payload or
    /// the payload has been tampered with.
    pub fn unseal_open_org_invite_data(
        &self,
        sealed: SealedOpenOrgInvite,
    ) -> Result<OpenOrgInvite, RegistrationError> {
        sealed.sealed_data.unseal(&sealed.high_entropy_secret)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::Client;

    use super::*;

    fn sample_input() -> OpenOrgInvite {
        OpenOrgInvite {
            organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".to_string(),
            invite_link_code: "abcd1234efgh5678".to_string(),
            invite_secret: "raw-invite-secret-material-base64url".to_string(),
        }
    }

    #[test]
    fn sealed_open_org_invite_json_wire_shape_is_stable() {
        // Locks the JSON wire: two-key camelCase object, both values as strings.
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);
        let sealed = registration_client
            .seal_open_org_invite_data(sample_input())
            .expect("seal should succeed");

        let json = serde_json::to_value(&sealed).expect("serialize");
        let obj = json.as_object().expect("must be a JSON object");
        assert_eq!(obj.len(), 2, "no extra or missing fields");
        assert!(
            obj.get("sealedData")
                .expect("sealedData key must be present")
                .is_string(),
            "sealedData must serialize as a JSON string"
        );
        assert!(
            obj.get("highEntropySecret")
                .expect("highEntropySecret key must be present")
                .is_string(),
            "highEntropySecret must serialize as a JSON string"
        );
    }
}
