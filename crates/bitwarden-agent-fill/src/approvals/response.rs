use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{
    KeyStoreContext, generate_versioned_sealable,
    safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use bitwarden_vault::CipherId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{AgentFillApprovalId, Challenge, sealed::SealedApproval};
use crate::AgentFillApprovalError;

/// Why the user denied an approval request.
#[bitwarden_ffi::wasm_record]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum DenyReason {
    /// The request is for an account other than the one the user meant.
    WrongAccount,
    /// The user didn't ask the agent to fill anything. Pauses the connection.
    NotRequested,
}

/// The user's answer to an approval request.
#[bitwarden_ffi::wasm_record]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ApprovalDecision {
    /// The user approved the fill with the chosen item.
    Approved {
        /// The item to fill.
        cipher_id: CipherId,
    },
    /// The user denied the fill.
    Denied {
        /// Why the user denied it, if they said.
        reason: Option<DenyReason>,
    },
}

// The types below are the sealed wire format. The decision is stored loosely, as a kind plus
// optional fields, so a malformed decision unseals and is then rejected with `InvalidDecision`.

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
enum ApprovalDecisionKindV1 {
    Approved,
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
enum DenyReasonV1 {
    WrongAccount,
    NotRequested,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct ApprovalResponseDataV1 {
    approval_request_id: AgentFillApprovalId,
    challenge: Challenge,
    decision: ApprovalDecisionKindV1,
    cipher_id: Option<CipherId>,
    deny_reason: Option<DenyReasonV1>,
    expires_at: DateTime<Utc>,
}

impl SealableData for ApprovalResponseDataV1 {}

generate_versioned_sealable!(
    ApprovalResponseData,
    DataEnvelopeNamespace::AgentFillApprovalResponse,
    [ApprovalResponseDataV1 => "1"]
);

impl ApprovalResponseDataV1 {
    pub(super) fn new(
        approval_request_id: AgentFillApprovalId,
        challenge: Challenge,
        decision: ApprovalDecision,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let (decision, cipher_id, deny_reason) = match decision {
            ApprovalDecision::Approved { cipher_id } => {
                (ApprovalDecisionKindV1::Approved, Some(cipher_id), None)
            }
            ApprovalDecision::Denied { reason } => (
                ApprovalDecisionKindV1::Denied,
                None,
                reason.map(|r| match r {
                    DenyReason::WrongAccount => DenyReasonV1::WrongAccount,
                    DenyReason::NotRequested => DenyReasonV1::NotRequested,
                }),
            ),
        };
        Self {
            approval_request_id,
            challenge,
            decision,
            cipher_id,
            deny_reason,
            expires_at,
        }
    }

    pub(super) fn approval_request_id(&self) -> AgentFillApprovalId {
        self.approval_request_id
    }

    pub(super) fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    pub(super) fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Returns the decision if it is well formed: an approval carries a cipher ID and no deny
    /// reason, and a denial carries no cipher ID.
    pub(super) fn decision(&self) -> Result<ApprovalDecision, AgentFillApprovalError> {
        match (self.decision, self.cipher_id, self.deny_reason) {
            (ApprovalDecisionKindV1::Approved, Some(cipher_id), None) => {
                Ok(ApprovalDecision::Approved { cipher_id })
            }
            (ApprovalDecisionKindV1::Denied, None, reason) => Ok(ApprovalDecision::Denied {
                reason: reason.map(|r| match r {
                    DenyReasonV1::WrongAccount => DenyReason::WrongAccount,
                    DenyReasonV1::NotRequested => DenyReason::NotRequested,
                }),
            }),
            _ => Err(AgentFillApprovalError::InvalidDecision),
        }
    }

    /// Seals this response under the `AgentFillApprovalResponse` namespace.
    pub(super) fn seal(
        self,
        wrapping_key: &SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<SealedApproval, AgentFillApprovalError> {
        SealedApproval::seal(ApprovalResponseData::from(self), wrapping_key, ctx)
    }

    /// Opens a response sealed under the `AgentFillApprovalResponse` namespace.
    pub(super) fn unseal(
        sealed: &SealedApproval,
        wrapping_key: &SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<Self, AgentFillApprovalError> {
        match sealed.unseal::<ApprovalResponseData>(wrapping_key, ctx)? {
            ApprovalResponseData::ApprovalResponseDataV1(data) => Ok(data),
        }
    }
}

#[cfg(test)]
impl ApprovalResponseDataV1 {
    /// Builds a response with an arbitrary, possibly malformed, decision.
    pub(super) fn new_unchecked(
        approval_request_id: AgentFillApprovalId,
        challenge: Challenge,
        approved: bool,
        cipher_id: Option<CipherId>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            approval_request_id,
            challenge,
            decision: if approved {
                ApprovalDecisionKindV1::Approved
            } else {
                ApprovalDecisionKindV1::Denied
            },
            cipher_id,
            deny_reason: None,
            expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use bitwarden_encoding::B64;

    use super::*;

    fn test_response(decision: ApprovalDecision) -> ApprovalResponseDataV1 {
        ApprovalResponseDataV1::new(
            "6f1e2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b".parse().unwrap(),
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
                .parse()
                .unwrap(),
            decision,
            "2026-01-01T12:05:00Z".parse().unwrap(),
        )
    }

    fn test_approved() -> ApprovalDecision {
        ApprovalDecision::Approved {
            cipher_id: "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".parse().unwrap(),
        }
    }

    fn test_denied() -> ApprovalDecision {
        ApprovalDecision::Denied {
            reason: Some(DenyReason::NotRequested),
        }
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key = ctx.generate_symmetric_key();

        #[allow(deprecated)]
        let key = ctx.dangerous_get_symmetric_key(wrapping_key).unwrap();
        println!(
            "const TEST_VECTOR_WRAPPING_KEY: &str = \"{}\";",
            key.to_base64()
        );

        for (name, decision) in [("APPROVED", test_approved()), ("DENIED", test_denied())] {
            let opaque = test_response(decision.clone())
                .seal(&wrapping_key, &mut ctx)
                .unwrap()
                .to_opaque_string()
                .unwrap();
            let restored = SealedApproval::from_opaque_string(&opaque).unwrap();
            let unsealed =
                ApprovalResponseDataV1::unseal(&restored, &wrapping_key, &mut ctx).unwrap();
            assert_eq!(unsealed.decision().unwrap(), decision);
            println!("const TEST_VECTOR_SEALED_RESPONSE_{name}: &str = r#\"{opaque}\"#;");
        }
    }

    const TEST_VECTOR_WRAPPING_KEY: &str =
        "n4JFKTOEyZ0Rtl0PheswcCH/017gZfkcUV1B1ui15KefDUvhmYumXoaidv/LU6BLkw8DVTRojZbyqchyeOx29g==";
    const TEST_VECTOR_SEALED_RESPONSE_APPROVED: &str = r#"{"format_version":1,"wrapped_cek":"2.AwPM4QPp/fNq4Gl0t7703g==|KEKHgk4GbBKsE8FhhKS6vbLVnzoXWN1Cb5mK0U+uP2UnJpo0C2hds9qHrWTefz8c7DMxzT3uyiDbjzuiOXCVQyB4PPZRtYBLx0/skDZRv0o=|Ox3tFaVbqXT69w4kYuOUmK7r/xyYDUtCMhV10JLgv0A=","envelope":"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUMzt3xcCWjv8AB8q9ZPm6Cw6AAE4gQI6AAE4gAWhBUw85Y92XoLChyqTAvNY3AY6+GWr1oRtvak2CpNznUwlp0TMk08yODL9MnG8JlRdc1jvamZ9YCNDjYk3Xg93j9gC/gbm6je3bdjs5OQn7vSK4netKe+Tx4pTd92ihDmqD9hPwN5VKFjHzCbaw+QCAYWvr0sj5gWrJtnfqHIgD+5SHLDYZMx7Ic3dGoqZeVE77UKxq9EX5nswPG8pK/hzOceDKrbO3B2pVetR6kukSswL8aJ+Eh7VlTtJEN0UKWomhTJZxHPC5Xp5+QpNeBDf5p788u8gUndcB4Lf9s4FJeIUlPpgfG0/q5dLON4="}"#;
    const TEST_VECTOR_SEALED_RESPONSE_DENIED: &str = r#"{"format_version":1,"wrapped_cek":"2.Y7cAm368PWx5cnNLnSvwQw==|I9nZzQqrcDot1GmLNifgYnFov3kD4M/8EjJmnPG3kftojetLzGhQGomI/aC0cVsofAV5CsbfwbJUwVW0XORYGIytWIJH8YGQ1iWHOD6eRzQ=|1zZPnwmB8vPrZwpGKk0pDlTiO+foIeIxcHRo4ZF7xoc=","envelope":"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUHBXOef6flsgOjkpcLSPXyc6AAE4gQI6AAE4gAWhBUyHIRBcwiFWmu+u/2lY1pkEEDWmu4wNj48tjVeqZ02Bo7bqOYxKQdD7aIkH53Ba4hTtuzo7/T+W/wSqqEw97NQtdUdWezkfuKaBTL3XWqlAkOuVc8o2b0mq0iY4jAAijBJrPQP/kIvWU3/oEC3v6G2mpcIcTk5BGcwjCGXHdnzCl6X/o2YLohL7trt5Uu7OBaKuNBydXLwQl7rinQqXjQIsHByE9UC4Q1X3cKrYbgFrfXT6bI8xq5k5Rxo6480AYXQKqm3+Za88nLQYXSTjZZaBbr7/nB+qKQ8eq+gIre9hUSLM0Bw="}"#;

    #[test]
    fn test_recorded_sealed_response_test_vectors() {
        let wrapping_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_WRAPPING_KEY).unwrap()).unwrap();
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key_id = ctx.add_local_symmetric_key(wrapping_key);

        for (vector, decision) in [
            (TEST_VECTOR_SEALED_RESPONSE_APPROVED, test_approved()),
            (TEST_VECTOR_SEALED_RESPONSE_DENIED, test_denied()),
        ] {
            let sealed = SealedApproval::from_opaque_string(vector).expect(
                "ApprovalResponseData format has changed in a backwards-incompatible way. \
                 Existing sealed responses must remain deserializable.",
            );
            let unsealed = ApprovalResponseDataV1::unseal(&sealed, &wrapping_key_id, &mut ctx)
                .expect(
                    "ApprovalResponseData format has changed in a backwards-incompatible way. \
                     Existing sealed responses must remain deserializable.",
                );

            assert_eq!(unsealed, test_response(decision));
        }
    }
}
