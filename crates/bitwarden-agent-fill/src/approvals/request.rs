use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{
    KeyStoreContext, generate_versioned_sealable,
    safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use serde::{Deserialize, Serialize};

use super::{Challenge, sealed::SealedApproval};
use crate::AgentFillApprovalError;

/// The kind of item an agent asked to fill.
#[bitwarden_ffi::wasm_record]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ApprovalCipherType {
    /// A login, matched against the request's tab URL.
    Login,
    /// A card.
    Card,
}

/// What the approving device shows for an approval request.
#[bitwarden_ffi::wasm_record]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ApprovalRequestView {
    /// The kind of item to fill.
    pub cipher_type: ApprovalCipherType,
    /// The tab's URL, from the extension. Logins are matched against it.
    pub tab_url: String,
    /// The tab's domain, from the extension. Shown on the approval screen.
    pub domain: String,
    /// The name the user gave the agent connection, such as "Claude Desktop".
    pub connection_name: String,
    /// The extension's display name, such as "Chrome".
    pub browser_name: String,
}

// The types below are the sealed wire format. They are kept separate from the public types so the
// bindings' serde attributes can't change what is sealed. Any change needs a new version.

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
enum ApprovalCipherTypeV1 {
    Login,
    Card,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct ApprovalRequestDataV1 {
    cipher_type: ApprovalCipherTypeV1,
    tab_url: String,
    domain: String,
    connection_name: String,
    browser_name: String,
    challenge: Challenge,
}

impl SealableData for ApprovalRequestDataV1 {}

generate_versioned_sealable!(
    ApprovalRequestData,
    DataEnvelopeNamespace::AgentFillApprovalRequest,
    [ApprovalRequestDataV1 => "1"]
);

impl ApprovalRequestDataV1 {
    pub(super) fn new(view: &ApprovalRequestView, challenge: &Challenge) -> Self {
        Self {
            cipher_type: match view.cipher_type {
                ApprovalCipherType::Login => ApprovalCipherTypeV1::Login,
                ApprovalCipherType::Card => ApprovalCipherTypeV1::Card,
            },
            tab_url: view.tab_url.clone(),
            domain: view.domain.clone(),
            connection_name: view.connection_name.clone(),
            browser_name: view.browser_name.clone(),
            challenge: challenge.clone(),
        }
    }

    pub(super) fn into_parts(self) -> (ApprovalRequestView, Challenge) {
        let view = ApprovalRequestView {
            cipher_type: match self.cipher_type {
                ApprovalCipherTypeV1::Login => ApprovalCipherType::Login,
                ApprovalCipherTypeV1::Card => ApprovalCipherType::Card,
            },
            tab_url: self.tab_url,
            domain: self.domain,
            connection_name: self.connection_name,
            browser_name: self.browser_name,
        };
        (view, self.challenge)
    }

    /// Seals this request under the `AgentFillApprovalRequest` namespace.
    pub(super) fn seal(
        self,
        wrapping_key: &SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<SealedApproval, AgentFillApprovalError> {
        SealedApproval::seal(ApprovalRequestData::from(self), wrapping_key, ctx)
    }

    /// Opens a request sealed under the `AgentFillApprovalRequest` namespace.
    pub(super) fn unseal(
        sealed: &SealedApproval,
        wrapping_key: &SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<Self, AgentFillApprovalError> {
        match sealed.unseal::<ApprovalRequestData>(wrapping_key, ctx)? {
            ApprovalRequestData::ApprovalRequestDataV1(data) => Ok(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use bitwarden_encoding::B64;

    use super::*;

    fn test_request() -> ApprovalRequestDataV1 {
        let view = ApprovalRequestView {
            cipher_type: ApprovalCipherType::Login,
            tab_url: "https://example.com/login".to_string(),
            domain: "example.com".to_string(),
            connection_name: "Claude Desktop".to_string(),
            browser_name: "Chrome".to_string(),
        };
        let challenge: Challenge = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
            .parse()
            .unwrap();
        ApprovalRequestDataV1::new(&view, &challenge)
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vector() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key = ctx.generate_symmetric_key();

        let sealed = test_request().seal(&wrapping_key, &mut ctx).unwrap();
        let opaque = sealed.to_opaque_string().unwrap();

        let restored = SealedApproval::from_opaque_string(&opaque).unwrap();
        assert_eq!(
            ApprovalRequestDataV1::unseal(&restored, &wrapping_key, &mut ctx).unwrap(),
            test_request()
        );

        #[allow(deprecated)]
        let key = ctx.dangerous_get_symmetric_key(wrapping_key).unwrap();
        println!(
            "const TEST_VECTOR_WRAPPING_KEY: &str = \"{}\";",
            key.to_base64()
        );
        println!("const TEST_VECTOR_SEALED_REQUEST: &str = r#\"{opaque}\"#;");
    }

    const TEST_VECTOR_WRAPPING_KEY: &str =
        "J+6ZT0pz37KWFS6kSKT0WDWRTHzklf0nH5AN2IlHQjVEtKnYopqzgGZSUyLpwO8RNGBoVHmHVXZqr+cnue54cQ==";
    const TEST_VECTOR_SEALED_REQUEST: &str = r#"{"format_version":1,"wrapped_cek":"2.qKtFI8RKHOIA8ygld3fByg==|a3itw06PX9G7Pb3r9ym0+mrqJcOjSTenCaM86gD5kCEb56rQWFv9fsQoOBbXOauWkjbencqnpsPrNkR8Gxe80y4iv7abx+tiiDj98QdZvC0=|njJkOxztSLFcqq0XK8fLEbnziOmzHV+ny7T6Qak8Zqk=","envelope":"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUKjk0L0U4nKc+ueWEZJBQ6A6AAE4gQI6AAE4gAShBUzJZvePtOROSbd2+9dY2EDor+hjPFeoGNeJvDq6pF2ujlPqQv7+epqUOPBiW1jiIBLRzBPN/MIN0raDfyj6rMuB+vlb56NFoXKZuV3OVGywzGD0TUyIXnlVIA0gGb/WdTSREKJrNojg2nrGJQTE+BmMIcM4SAAW5+SxL9eXHSA12/n1vEQCv4qPodAS7+XiBBa0jCG/AIcvPPMiTV5v+mh1knc5ig33pAUAPhz9BH/k2Gpvob8mt2PjN2oKnNf1YIBzg3j+Wgd6ZOnUndhKr9SB9zDh5mpBWv1cqCjH3W3Qd3fMq78uOA=="}"#;

    #[test]
    fn test_recorded_sealed_request_test_vector() {
        let wrapping_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_WRAPPING_KEY).unwrap()).unwrap();
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key_id = ctx.add_local_symmetric_key(wrapping_key);

        let sealed = SealedApproval::from_opaque_string(TEST_VECTOR_SEALED_REQUEST).expect(
            "ApprovalRequestData format has changed in a backwards-incompatible way. Existing \
             sealed requests must remain deserializable.",
        );
        let unsealed = ApprovalRequestDataV1::unseal(&sealed, &wrapping_key_id, &mut ctx).expect(
            "ApprovalRequestData format has changed in a backwards-incompatible way. Existing \
             sealed requests must remain deserializable.",
        );

        assert_eq!(unsealed, test_request());
    }
}
