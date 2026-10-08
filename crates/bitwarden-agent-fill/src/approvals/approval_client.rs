use bitwarden_core::{
    FromClient,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::KeyStore;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::{
    AgentFillApprovalId, ApprovalDecision, ApprovalRequestView, Challenge,
    request::ApprovalRequestDataV1, response::ApprovalResponseDataV1, sealed::SealedApproval,
};
use crate::AgentFillApprovalError;

/// How long a response stays valid after the device answers. Matches the server's
/// `ExpirationDate` window and the desktop app's approval timer.
const RESPONSE_LIFETIME: Duration = Duration::minutes(5);

/// What the desktop app keeps in memory while an approval request is open. Pass it to
/// [`AgentFillApprovalClient::verify_response`] and drop it once a decision is accepted.
#[bitwarden_ffi::wasm_record]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PendingApproval {
    /// The request as sealed.
    pub view: ApprovalRequestView,
    /// The challenge a valid response must echo.
    pub challenge: Challenge,
}

/// The result of [`AgentFillApprovalClient::create_request`].
#[bitwarden_ffi::wasm_record]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CreatedApprovalRequest {
    /// The sealed request to send to the server.
    pub sealed_request: String,
    /// What the desktop app keeps until the request ends.
    pub pending: PendingApproval,
}

/// An approval request opened for display. Pass it back to
/// [`AgentFillApprovalClient::seal_response`] to answer it.
#[bitwarden_ffi::wasm_record]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct OpenedApprovalRequest {
    /// What to show the user.
    pub view: ApprovalRequestView,
    /// The challenge the response echoes.
    pub challenge: Challenge,
}

/// Seals, opens and verifies agent fill approval requests and responses with the user key.
#[derive(FromClient)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[bitwarden_ffi::wasm_object]
pub struct AgentFillApprovalClient {
    key_store: KeyStore<KeySlotIds>,
}

#[bitwarden_ffi::wasm_export]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl AgentFillApprovalClient {
    /// Desktop. Seals a new request with a fresh challenge, and returns the sealed request and
    /// what the desktop keeps until the request ends.
    pub fn create_request(
        &self,
        request: ApprovalRequestView,
    ) -> Result<CreatedApprovalRequest, AgentFillApprovalError> {
        let challenge = Challenge::make();
        let mut ctx = self.key_store.context();
        let sealed = ApprovalRequestDataV1::new(&request, &challenge)
            .seal(&SymmetricKeySlotId::User, &mut ctx)?;
        Ok(CreatedApprovalRequest {
            sealed_request: sealed.to_opaque_string()?,
            pending: PendingApproval {
                view: request,
                challenge,
            },
        })
    }

    /// Phones and desktop. Unseals a request for display.
    pub fn open_request(
        &self,
        sealed_request: String,
    ) -> Result<OpenedApprovalRequest, AgentFillApprovalError> {
        let sealed = SealedApproval::from_opaque_string(&sealed_request)?;
        let mut ctx = self.key_store.context();
        let (view, challenge) =
            ApprovalRequestDataV1::unseal(&sealed, &SymmetricKeySlotId::User, &mut ctx)?
                .into_parts();
        Ok(OpenedApprovalRequest { view, challenge })
    }

    /// Phones and desktop. Seals the answer to an opened request. The response expires five
    /// minutes from now.
    pub fn seal_response(
        &self,
        approval_request_id: AgentFillApprovalId,
        request: OpenedApprovalRequest,
        decision: ApprovalDecision,
    ) -> Result<String, AgentFillApprovalError> {
        self.seal_response_at(approval_request_id, request, decision, Utc::now())
    }

    /// Desktop. Unseals a response and accepts its decision only if it answers
    /// `approval_request_id`, echoes the pending request's challenge, hasn't expired, and is well
    /// formed.
    pub fn verify_response(
        &self,
        pending: PendingApproval,
        approval_request_id: AgentFillApprovalId,
        sealed_response: String,
    ) -> Result<ApprovalDecision, AgentFillApprovalError> {
        self.verify_response_at(pending, approval_request_id, sealed_response, Utc::now())
    }
}

impl AgentFillApprovalClient {
    fn seal_response_at(
        &self,
        approval_request_id: AgentFillApprovalId,
        request: OpenedApprovalRequest,
        decision: ApprovalDecision,
        now: DateTime<Utc>,
    ) -> Result<String, AgentFillApprovalError> {
        let mut ctx = self.key_store.context();
        ApprovalResponseDataV1::new(
            approval_request_id,
            request.challenge,
            decision,
            now + RESPONSE_LIFETIME,
        )
        .seal(&SymmetricKeySlotId::User, &mut ctx)?
        .to_opaque_string()
    }

    fn verify_response_at(
        &self,
        pending: PendingApproval,
        approval_request_id: AgentFillApprovalId,
        sealed_response: String,
        now: DateTime<Utc>,
    ) -> Result<ApprovalDecision, AgentFillApprovalError> {
        let sealed = SealedApproval::from_opaque_string(&sealed_response)?;
        let mut ctx = self.key_store.context();
        let data = ApprovalResponseDataV1::unseal(&sealed, &SymmetricKeySlotId::User, &mut ctx)?;

        if data.approval_request_id() != approval_request_id {
            return Err(AgentFillApprovalError::RequestIdMismatch);
        }
        // `Challenge` equality is constant time.
        if *data.challenge() != pending.challenge {
            return Err(AgentFillApprovalError::ChallengeMismatch);
        }
        if data.expires_at() <= now {
            return Err(AgentFillApprovalError::Expired);
        }
        data.decision()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_vault::CipherId;

    use super::*;
    use crate::{ApprovalCipherType, DenyReason};

    fn client() -> AgentFillApprovalClient {
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = key_store.context_mut();
            let key = ctx.generate_symmetric_key();
            ctx.persist_symmetric_key(key, SymmetricKeySlotId::User)
                .unwrap();
        }
        AgentFillApprovalClient { key_store }
    }

    fn view() -> ApprovalRequestView {
        ApprovalRequestView {
            cipher_type: ApprovalCipherType::Login,
            tab_url: "https://example.com/login".to_string(),
            domain: "example.com".to_string(),
            connection_name: "Claude Desktop".to_string(),
            browser_name: "Chrome".to_string(),
        }
    }

    fn approved() -> ApprovalDecision {
        ApprovalDecision::Approved {
            cipher_id: CipherId::new_v4(),
        }
    }

    /// Seals a response directly, bypassing `seal_response`'s typed decision.
    fn seal_raw(client: &AgentFillApprovalClient, data: ApprovalResponseDataV1) -> String {
        let mut ctx = client.key_store.context();
        data.seal(&SymmetricKeySlotId::User, &mut ctx)
            .unwrap()
            .to_opaque_string()
            .unwrap()
    }

    #[test]
    fn create_request_returns_sealed_request_and_pending() {
        let client = client();
        let created = client.create_request(view()).unwrap();

        let json: serde_json::Value = serde_json::from_str(&created.sealed_request).unwrap();
        assert_eq!(json["format_version"], 1);
        assert!(json["wrapped_cek"].is_string());
        assert!(json["envelope"].is_string());
        assert_eq!(created.pending.view, view());
    }

    #[test]
    fn create_request_uses_a_new_challenge_each_time() {
        let client = client();
        let first = client.create_request(view()).unwrap();
        let second = client.create_request(view()).unwrap();
        assert_ne!(first.pending.challenge, second.pending.challenge);
    }

    #[test]
    fn open_request_returns_view_and_challenge() {
        let client = client();
        let created = client.create_request(view()).unwrap();

        let opened = client.open_request(created.sealed_request).unwrap();

        assert_eq!(opened.view, view());
        assert_eq!(opened.challenge, created.pending.challenge);
    }

    #[test]
    fn verify_response_accepts_an_approval() {
        let client = client();
        let id = AgentFillApprovalId::new_v4();
        let created = client.create_request(view()).unwrap();
        let opened = client.open_request(created.sealed_request).unwrap();
        let decision = approved();

        let sealed = client.seal_response(id, opened, decision.clone()).unwrap();

        assert_eq!(
            client.verify_response(created.pending, id, sealed).unwrap(),
            decision
        );
    }

    #[test]
    fn verify_response_accepts_a_denial() {
        let client = client();
        let id = AgentFillApprovalId::new_v4();
        let created = client.create_request(view()).unwrap();
        let opened = client.open_request(created.sealed_request).unwrap();

        for decision in [
            ApprovalDecision::Denied { reason: None },
            ApprovalDecision::Denied {
                reason: Some(DenyReason::WrongAccount),
            },
            ApprovalDecision::Denied {
                reason: Some(DenyReason::NotRequested),
            },
        ] {
            let sealed = client
                .seal_response(id, opened.clone(), decision.clone())
                .unwrap();
            assert_eq!(
                client
                    .verify_response(created.pending.clone(), id, sealed)
                    .unwrap(),
                decision
            );
        }
    }

    #[test]
    fn verify_response_rejects_a_sealed_request() {
        let client = client();
        let created = client.create_request(view()).unwrap();

        let result = client.verify_response(
            created.pending,
            AgentFillApprovalId::new_v4(),
            created.sealed_request,
        );

        assert!(matches!(result, Err(AgentFillApprovalError::Unseal)));
    }

    #[test]
    fn open_request_rejects_a_sealed_response() {
        let client = client();
        let created = client.create_request(view()).unwrap();
        let opened = client.open_request(created.sealed_request).unwrap();
        let sealed = client
            .seal_response(AgentFillApprovalId::new_v4(), opened, approved())
            .unwrap();

        let result = client.open_request(sealed);

        assert!(matches!(result, Err(AgentFillApprovalError::Unseal)));
    }

    #[test]
    fn verify_response_rejects_another_request_id() {
        let client = client();
        let created = client.create_request(view()).unwrap();
        let opened = client.open_request(created.sealed_request).unwrap();
        let sealed = client
            .seal_response(AgentFillApprovalId::new_v4(), opened, approved())
            .unwrap();

        let result = client.verify_response(created.pending, AgentFillApprovalId::new_v4(), sealed);

        assert!(matches!(
            result,
            Err(AgentFillApprovalError::RequestIdMismatch)
        ));
    }

    #[test]
    fn verify_response_rejects_another_challenge() {
        let client = client();
        let id = AgentFillApprovalId::new_v4();
        let pending = client.create_request(view()).unwrap().pending;
        let other = client.create_request(view()).unwrap();
        let other_opened = client.open_request(other.sealed_request).unwrap();
        let sealed = client.seal_response(id, other_opened, approved()).unwrap();

        let result = client.verify_response(pending, id, sealed);

        assert!(matches!(
            result,
            Err(AgentFillApprovalError::ChallengeMismatch)
        ));
    }

    #[test]
    fn verify_response_rejects_an_expired_response() {
        let client = client();
        let id = AgentFillApprovalId::new_v4();
        let created = client.create_request(view()).unwrap();
        let opened = client.open_request(created.sealed_request).unwrap();
        let answered_at = Utc::now();
        let sealed = client
            .seal_response_at(id, opened, approved(), answered_at)
            .unwrap();

        let before_expiry = answered_at + RESPONSE_LIFETIME - Duration::seconds(1);
        assert!(
            client
                .verify_response_at(created.pending.clone(), id, sealed.clone(), before_expiry)
                .is_ok()
        );

        let at_expiry = answered_at + RESPONSE_LIFETIME;
        let result = client.verify_response_at(created.pending, id, sealed, at_expiry);
        assert!(matches!(result, Err(AgentFillApprovalError::Expired)));
    }

    #[test]
    fn verify_response_rejects_an_approval_without_a_cipher_id() {
        let client = client();
        let id = AgentFillApprovalId::new_v4();
        let pending = client.create_request(view()).unwrap().pending;
        let sealed = seal_raw(
            &client,
            ApprovalResponseDataV1::new_unchecked(
                id,
                pending.challenge.clone(),
                true,
                None,
                Utc::now() + RESPONSE_LIFETIME,
            ),
        );

        let result = client.verify_response(pending, id, sealed);

        assert!(matches!(
            result,
            Err(AgentFillApprovalError::InvalidDecision)
        ));
    }

    #[test]
    fn verify_response_rejects_a_denial_with_a_cipher_id() {
        let client = client();
        let id = AgentFillApprovalId::new_v4();
        let pending = client.create_request(view()).unwrap().pending;
        let sealed = seal_raw(
            &client,
            ApprovalResponseDataV1::new_unchecked(
                id,
                pending.challenge.clone(),
                false,
                Some(CipherId::new_v4()),
                Utc::now() + RESPONSE_LIFETIME,
            ),
        );

        let result = client.verify_response(pending, id, sealed);

        assert!(matches!(
            result,
            Err(AgentFillApprovalError::InvalidDecision)
        ));
    }

    #[test]
    fn verify_response_rejects_another_users_key() {
        let desktop = client();
        let other_user = client();
        let id = AgentFillApprovalId::new_v4();
        let created = desktop.create_request(view()).unwrap();
        let opened = desktop.open_request(created.sealed_request).unwrap();
        let sealed = other_user.seal_response(id, opened, approved()).unwrap();

        let result = desktop.verify_response(created.pending, id, sealed);

        assert!(matches!(result, Err(AgentFillApprovalError::Unseal)));
    }

    #[test]
    fn open_request_rejects_another_users_key() {
        let created = client().create_request(view()).unwrap();

        let result = client().open_request(created.sealed_request);

        assert!(matches!(result, Err(AgentFillApprovalError::Unseal)));
    }

    #[test]
    fn verify_response_rejects_malformed_input() {
        let client = client();
        let pending = client.create_request(view()).unwrap().pending;

        for input in ["not json", "{}", r#"{"format_version":2}"#] {
            let result = client.verify_response(
                pending.clone(),
                AgentFillApprovalId::new_v4(),
                input.into(),
            );
            assert!(matches!(result, Err(AgentFillApprovalError::Unseal)));
        }
    }

    #[test]
    fn create_request_fails_without_a_user_key() {
        let client = AgentFillApprovalClient {
            key_store: KeyStore::default(),
        };

        let result = client.create_request(view());

        assert!(matches!(result, Err(AgentFillApprovalError::Seal)));
    }
}
