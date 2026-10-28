//! The vault side of a rotation attempt: the pre-flight dry run and the cipher write (including
//! the 409 re-check), plus fetching, checking and re-encrypting the cipher. The stage fixes how a
//! rejection is reported.

use bitwarden_api_api::models::CipherRequestModel;
use bitwarden_core::{OrganizationId, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
use bitwarden_pam::{
    RotationCipherError, RotationFailureCode, RotationSyncState, cipher_has_password,
    rotate_cipher_password,
};
use bitwarden_vault::Cipher;
use uuid::Uuid;

use super::{AbortReason, Attempt, CipherWritten, Halt, abort_from_api, halt_from_api};
use crate::{api::models::ApiError, error::SafeDetail, executor::retry::with_retries};

/// Where a cipher is checked, which fixes the sync state and the reason strings.
#[derive(Clone, Copy)]
enum Stage {
    /// Before the target is touched.
    PreFlight,
    /// After the target is rotated, just before the cipher write.
    PreWrite,
}

impl Stage {
    fn sync(self) -> RotationSyncState {
        match self {
            Stage::PreFlight => RotationSyncState::TargetUnchanged,
            Stage::PreWrite => RotationSyncState::TargetUpdated,
        }
    }
}

/// Picks the stage's `'static` reason string for `$suffix`.
macro_rules! stage_reason {
    ($stage:expr, $suffix:literal) => {
        match $stage {
            Stage::PreFlight => concat!("pre_flight_", $suffix),
            Stage::PreWrite => concat!("pre_write_", $suffix),
        }
    };
}

impl Attempt<'_> {
    /// Pre-flight cipher check, before the target is touched, so an unrotatable cipher (wrong
    /// organization or type, restricted, undecryptable) fails as target_unchanged.
    pub(super) async fn pre_flight(&self) -> Result<(), Halt> {
        let cipher = fetch_checked_cipher(self, Stage::PreFlight).await?;

        // Dry run of the cipher write with a placeholder password; the request is discarded.
        rotate_cipher(
            &self.api.key_store,
            self.ctx.organization_id,
            cipher,
            PRE_FLIGHT_PLACEHOLDER_PASSWORD,
            Stage::PreFlight,
        )?;
        Ok(())
    }

    /// Fetches the cipher and writes the new password. Not bounded by execute_by; the session's
    /// bearer refresh handles token expiry.
    pub(super) async fn write_cipher(&self, new_password: &str) -> Result<CipherWritten, Halt> {
        let Self {
            job,
            ctx,
            api,
            attempt_id,
            ..
        } = *self;

        // Repeats the pre-flight check; the target is already rotated, so this is target_updated.
        let cipher = fetch_checked_cipher(self, Stage::PreWrite).await?;

        tracing::debug!(attempt_id = %attempt_id, cipher_id = %job.cipher_id(), "cipher fetched");

        let request = rotate_cipher(
            &api.key_store,
            ctx.organization_id,
            cipher,
            new_password,
            Stage::PreWrite,
        )?;

        let result = with_retries(
            &ctx.retry_cfg,
            None, // no deadline
            || {
                let request = request.clone();
                async move {
                    api.put_cipher(attempt_id, request)
                        .await
                        .map_err(|e| (e.retry_class(), e))
                }
            },
        )
        .await;

        match result {
            Ok(()) => {
                tracing::info!(
                    attempt_id = %attempt_id,
                    cipher_id = %job.cipher_id(),
                    "step 5: cipher written"
                );
            }
            // A retried PUT repeats its `lastKnownRevisionDate`, so a 409 can follow a first try
            // that committed with its response lost. Only the vault's contents settle it.
            Err(ApiError::Rejected { .. }) => match cipher_write_landed(self, new_password).await {
                Ok(true) => {
                    tracing::info!(
                        attempt_id = %attempt_id,
                        cipher_id = %job.cipher_id(),
                        "step 5: cipher write confirmed after 409"
                    );
                }
                Ok(false) => {
                    return Err(Halt::report(
                        RotationFailureCode::CipherWriteRejected,
                        RotationSyncState::TargetUpdated,
                    ));
                }
                Err(reason) => return Err(Halt::Abort(reason)),
            },
            // The target credential already changed.
            Err(e) => return Err(halt_from_api(e, RotationSyncState::TargetUpdated)),
        }
        Ok(CipherWritten(()))
    }
}

/// Fetches the cipher with retries. Callers handle failure, since the sync state differs.
async fn fetch_cipher(attempt: &Attempt<'_>) -> Result<Cipher, ApiError> {
    let Attempt {
        api,
        ctx,
        attempt_id,
        ..
    } = *attempt;
    with_retries(&ctx.retry_cfg, None, move || async move {
        api.get_cipher(attempt_id)
            .await
            .map_err(|e| (e.retry_class(), e))
    })
    .await
}

/// Fetches the cipher and checks that it is the claim's.
async fn fetch_checked_cipher(attempt: &Attempt<'_>, stage: Stage) -> Result<Cipher, Halt> {
    let cipher = fetch_cipher(attempt)
        .await
        .map_err(|e| halt_from_api(e, stage.sync()))?;

    if cipher.id.map(Uuid::from) != Some(attempt.job.cipher_id()) {
        return Err(Halt::report_detail(
            RotationFailureCode::SealedDataRejected,
            SafeDetail::from_seal_rejection(stage_reason!(stage, "cipher_id_mismatch")),
            stage.sync(),
        ));
    }
    Ok(cipher)
}

/// Re-encrypts `cipher` with `new_password`, mapping a failure to the stage's halt.
fn rotate_cipher(
    key_store: &KeyStore<KeySlotIds>,
    organization_id: OrganizationId,
    cipher: Cipher,
    new_password: &str,
    stage: Stage,
) -> Result<CipherRequestModel, Halt> {
    rotate_cipher_password(key_store, organization_id, cipher, new_password)
        .map_err(|e| cipher_halt(&e, stage))
}

/// Whether the vault's cipher already holds `new_password`, so a rejected write did land. Any
/// failure to tell counts as not landed; only an abort is an error.
async fn cipher_write_landed(
    attempt: &Attempt<'_>,
    new_password: &str,
) -> Result<bool, AbortReason> {
    match fetch_cipher(attempt).await {
        Ok(cipher) => {
            Ok(cipher_has_password(&attempt.api.key_store, &cipher, new_password).unwrap_or(false))
        }
        Err(e) => abort_from_api(&e).map_or(Ok(false), Err),
    }
}

/// Stands in for the new password in the pre-flight dry run.
const PRE_FLIGHT_PLACEHOLDER_PASSWORD: &str = "pre-flight-placeholder";

/// Maps a cipher error to the stage's halt, with a fixed, content-free reason. A write-invalid
/// error only gets its own reason at pre-flight; at pre-write it is `CipherEncryptFailed`.
fn cipher_halt(err: &RotationCipherError, stage: Stage) -> Halt {
    use RotationCipherError as E;

    let reason = match (err, stage) {
        // The re-encrypted cipher produced an unusable request.
        (E::CipherDataPresent | E::Json(_), Stage::PreWrite) => {
            return Halt::report(
                RotationFailureCode::CipherEncryptFailed,
                RotationSyncState::TargetUpdated,
            );
        }
        (E::CipherDataPresent | E::Json(_), Stage::PreFlight) => "pre_flight_cipher_write_invalid",
        (E::CipherOrganizationMismatch, _) => stage_reason!(stage, "cipher_org_mismatch"),
        (E::CipherNotLogin, _) => stage_reason!(stage, "cipher_not_login"),
        (E::CipherRestricted, _) => stage_reason!(stage, "cipher_restricted"),
        (E::CipherWithoutItemKey, _) => stage_reason!(stage, "cipher_without_item_key"),
        // A `Crypto` error can't be split into decrypt or encrypt. Pre-flight runs the same
        // encryption on a placeholder password, so at either stage treat it as a rejected cipher.
        (E::Crypto(_), _) => stage_reason!(stage, "cipher_decrypt_failed"),
    };
    Halt::report_detail(
        RotationFailureCode::SealedDataRejected,
        SafeDetail::from_seal_rejection(reason),
        stage.sync(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bitwarden_api_api::models::CipherMiniResponseModel;
    use wiremock::ResponseTemplate;

    use super::*;
    use crate::{
        executor::rotation::tests::{Fixture, json_response},
        test_support::{
            KEYED_LOGIN_WITH_ATTACHMENT, KEYLESS_LOGIN, RESTRICTED_LOGIN, attachments_json,
            decrypt_body_field, keyed_login_json, org_store, test_org_id, vector_json,
        },
    };

    /// The parts of a reported halt: code, detail and sync state. Panics on an abort.
    fn report_parts(halt: Halt) -> (RotationFailureCode, Option<String>, RotationSyncState) {
        match halt {
            Halt::Report { code, detail, sync } => {
                (code, detail.map(|d| d.as_str().to_owned()), sync)
            }
            Halt::Abort(_) => panic!("expected a reported halt, got an abort"),
        }
    }

    /// The halt of a step that was expected to fail.
    fn halt_of<T>(result: Result<T, Halt>) -> Halt {
        match result {
            Err(halt) => halt,
            Ok(_) => panic!("expected a halt"),
        }
    }

    fn rejected(reason: &str) -> Option<String> {
        Some(format!("sealed data rejected: {reason}"))
    }

    fn cipher_from(json: serde_json::Value) -> Cipher {
        let model: CipherMiniResponseModel = serde_json::from_value(json).expect("model");
        Cipher::try_from(model).expect("cipher")
    }

    fn bad_json() -> RotationCipherError {
        RotationCipherError::Json(serde_json::from_str::<()>("x").unwrap_err())
    }

    // ---- cipher_halt ----

    /// A write-invalid error only gets its own reason at pre-flight; at pre-write it is
    /// `CipherEncryptFailed`. The other errors are covered by `rotate_cipher` below.
    #[test]
    fn cipher_halt_write_invalid_differs_by_stage() {
        use RotationCipherError as E;

        for err in [E::CipherDataPresent, bad_json()] {
            assert_eq!(
                report_parts(cipher_halt(&err, Stage::PreFlight)),
                (
                    RotationFailureCode::SealedDataRejected,
                    rejected("pre_flight_cipher_write_invalid"),
                    RotationSyncState::TargetUnchanged
                ),
                "{err} at pre-flight"
            );
            assert_eq!(
                report_parts(cipher_halt(&err, Stage::PreWrite)),
                (
                    RotationFailureCode::CipherEncryptFailed,
                    None,
                    RotationSyncState::TargetUpdated
                ),
                "{err} at pre-write"
            );
        }
    }

    // ---- rotate_cipher ----

    fn rotate(json: serde_json::Value, stage: Stage) -> Result<CipherRequestModel, Halt> {
        rotate_cipher(
            &org_store(),
            test_org_id(),
            cipher_from(json),
            "new-pw",
            stage,
        )
    }

    #[test]
    fn rotate_cipher_of_cipher_with_item_key_and_attachments_succeeds() {
        let json = vector_json(KEYED_LOGIN_WITH_ATTACHMENT);
        let request = rotate(json, Stage::PreFlight).ok().expect("rotates");

        let body = serde_json::to_value(&request).unwrap();
        assert_eq!(
            decrypt_body_field(&org_store(), &body, "/login/password"),
            "new-pw"
        );
        assert_eq!(body["attachments2"].as_object().map(|a| a.len()), Some(1));
    }

    /// A cipher that cannot be rotated is rejected with the stage's reason.
    #[test]
    fn rotate_cipher_rejects_unrotatable_ciphers_at_both_stages() {
        use bitwarden_crypto::{KeyEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm};

        let other_org = {
            let mut json = keyed_login_json();
            json["organizationId"] = uuid::Uuid::new_v4().to_string().into();
            json
        };
        let non_login = {
            let mut json = keyed_login_json();
            json["type"] = 2.into();
            json
        };
        // Lenient decryption would drop the field and the write would wipe it.
        let undecryptable = {
            let other = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let foreign = "x".encrypt_with_key(&other).unwrap().to_string();
            let mut json = keyed_login_json();
            json["notes"] = foreign.into();
            json
        };
        // A keyless cipher would make the vault generate an item key.
        let keyless = vector_json(KEYLESS_LOGIN);
        let keyless_with_attachments = {
            let mut json = vector_json(KEYLESS_LOGIN);
            json["attachments"] = attachments_json();
            json
        };

        let cases = [
            ("other organization", other_org, "cipher_org_mismatch"),
            ("non-login", non_login, "cipher_not_login"),
            (
                "restricted",
                vector_json(RESTRICTED_LOGIN),
                "cipher_restricted",
            ),
            (
                "undecryptable field",
                undecryptable,
                "cipher_decrypt_failed",
            ),
            ("without item key", keyless, "cipher_without_item_key"),
            (
                "attachments without item key",
                keyless_with_attachments,
                "cipher_without_item_key",
            ),
        ];

        for (label, json, reason) in cases {
            for (stage, prefix) in [
                (Stage::PreFlight, "pre_flight"),
                (Stage::PreWrite, "pre_write"),
            ] {
                let halt = halt_of(rotate(json.clone(), stage));
                assert_eq!(
                    report_parts(halt),
                    (
                        RotationFailureCode::SealedDataRejected,
                        rejected(&format!("{prefix}_{reason}")),
                        stage.sync()
                    ),
                    "{label} at {prefix}"
                );
            }
        }
    }

    /// A fixture serving `json` for every `GET /cipher`, for the keyed login claim.
    async fn serving(json: serde_json::Value) -> Fixture {
        Fixture::new(json_response(json), ResponseTemplate::new(200)).await
    }

    fn not_json() -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_string("NOT JSON")
            .insert_header("content-type", "application/json")
    }

    // ---- Attempt::write_cipher ----

    #[tokio::test]
    async fn write_cipher_writes_typed_cipher_with_history() {
        let json = keyed_login_json();
        let original_key = json["key"].as_str().unwrap().to_owned();
        assert_eq!(
            json["revisionDate"],
            crate::test_support::CIPHER_REVISION_DATE
        );
        let fixture = serving(json).await;

        assert!(fixture.attempt().write_cipher("new-pw").await.is_ok());

        let puts = fixture.requests_to("PUT", "/cipher").await;
        assert_eq!(puts.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&puts[0].body).expect("PUT body");
        let dec = |p| decrypt_body_field(&fixture.store, &body, p);

        // The item key is sent back unchanged, and the new fields decrypt under it.
        assert_eq!(body["key"], original_key.as_str());

        // The written password is the new one; the old ones are in history.
        assert_eq!(dec("/login/password"), "new-pw");
        assert_eq!(dec("/passwordHistory/0/password"), "old-password");
        assert_eq!(dec("/passwordHistory/1/password"), "older-password");
        assert!(body["login"]["passwordRevisionDate"].is_string());
        // The wire format drops the fraction of `CIPHER_REVISION_DATE`; the server's revision
        // check allows a one-second difference.
        assert_eq!(body["lastKnownRevisionDate"], "2024-06-01T12:00:00Z");
        assert!(body["data"].is_null());
        assert_eq!(body["organizationId"], test_org_id().to_string());
        assert_eq!(body["type"], 1);
        assert_eq!(dec("/login/username"), "svc-account");
        assert_eq!(dec("/login/uris/0/uri"), "https://db.example.com");
        assert_eq!(dec("/name"), "Prod database");
    }

    /// A `get_cipher` protocol error after a successful rotate reports `target_updated`.
    #[tokio::test]
    async fn write_cipher_protocol_error_reports_internal_target_updated() {
        let fixture = Fixture::new(not_json(), ResponseTemplate::new(200)).await;

        let halt = halt_of(fixture.attempt().write_cipher("new-pw").await);
        assert_eq!(
            report_parts(halt),
            (
                RotationFailureCode::Internal,
                None,
                RotationSyncState::TargetUpdated
            )
        );
        assert!(fixture.requests_to("PUT", "/cipher").await.is_empty());
    }

    #[tokio::test]
    async fn write_cipher_rejects_cipher_id_mismatch_as_target_updated() {
        let mut json = keyed_login_json();
        json["id"] = uuid::Uuid::new_v4().to_string().into();
        let fixture = serving(json).await;

        let halt = halt_of(fixture.attempt().write_cipher("new-pw").await);
        assert_eq!(
            report_parts(halt),
            (
                RotationFailureCode::SealedDataRejected,
                rejected("pre_write_cipher_id_mismatch"),
                RotationSyncState::TargetUpdated
            )
        );
        assert!(fixture.requests_to("PUT", "/cipher").await.is_empty());
    }

    /// Answers `PUT /cipher` with a 409 and keeps the body, as a write that committed and was
    /// retried would see.
    struct ConflictAfterCommit(Arc<Mutex<Option<serde_json::Value>>>);

    impl wiremock::Respond for ConflictAfterCommit {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            *self.0.lock().unwrap() =
                Some(serde_json::from_slice(&request.body).expect("PUT body"));
            ResponseTemplate::new(409)
        }
    }

    /// Serves the cipher as the vault holds it: the fixture, carrying the password written by the
    /// PUT (if any). The PUT keeps the item key, so its encrypted password decrypts in the
    /// fixture.
    struct VaultAfterPut(Arc<Mutex<Option<serde_json::Value>>>);

    impl wiremock::Respond for VaultAfterPut {
        fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
            let mut json = keyed_login_json();
            if let Some(put) = self.0.lock().unwrap().as_ref() {
                json["login"]["password"] = put["login"]["password"].clone();
            }
            json_response(json)
        }
    }

    /// A 409 on the PUT whose write did land (the vault holds the new password) is a success.
    #[tokio::test]
    async fn write_cipher_409_with_new_password_in_vault_succeeds() {
        let put = Arc::new(Mutex::new(None));
        let fixture = Fixture::new(VaultAfterPut(Arc::clone(&put)), ConflictAfterCommit(put)).await;

        assert!(fixture.attempt().write_cipher("new-pw").await.is_ok());
        assert_eq!(fixture.requests_to("PUT", "/cipher").await.len(), 1);
    }

    /// A 409 on the PUT with the old password still in the vault is a rejected write.
    #[tokio::test]
    async fn write_cipher_409_with_old_password_in_vault_is_rejected() {
        let fixture = Fixture::new(
            json_response(keyed_login_json()),
            ResponseTemplate::new(409),
        )
        .await;

        let halt = halt_of(fixture.attempt().write_cipher("new-pw").await);
        assert_eq!(
            report_parts(halt),
            (
                RotationFailureCode::CipherWriteRejected,
                None,
                RotationSyncState::TargetUpdated
            )
        );
        assert_eq!(fixture.requests_to("PUT", "/cipher").await.len(), 1);
    }
}
