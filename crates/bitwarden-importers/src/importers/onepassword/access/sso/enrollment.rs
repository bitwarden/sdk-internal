//! Enrolling this device as a trusted one: ask the server to start an enrollment, wait for the user
//! to approve it on an enrolled device, then take the credentials that device shares.
//!
//! The UI drives the enrollment through an `SsoEnrollmentContext`, which shows the progress, asks
//! for the verification code and can cancel at any point.

use std::pin::pin;

use bitwarden_threading::time;
use futures::future::{Either, select};
use reqwest::StatusCode;
use serde_json::json;
use zeroize::Zeroizing;

use super::{
    super::{
        error::OnePasswordError,
        rest::RestClient,
        wire::{self, CredentialBundle},
    },
    Timing,
    cpace::{EnrollmentSession, Exchange, perform_cpace},
    ui::{
        EnrollmentStatus, SsoEnrollmentContext, SsoEnrollmentResult, SsoUi, VerificationCodeResult,
    },
};

/// How many verification codes the user may try, as many as 1Password's own clients allow.
const MAX_CODE_ATTEMPTS: u32 = 3;

/// What the server reports about an enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerStatus {
    /// The user has not picked an enrolled device to approve the request yet.
    SelectingVerifier,
    /// An enrolled device approved the request and shows the verification code.
    WaitingForCode,
    /// A stage of the code check, named after 1Password's web client.
    PendingValidation,
    /// The user denied the request on the enrolled device.
    Denied,
    /// Anything else the server may report.
    Unknown,
}

impl ServerStatus {
    fn parse(status: &str) -> ServerStatus {
        match status {
            "SELECTING_VERIFIER" => ServerStatus::SelectingVerifier,
            "WAITING_FOR_CODE" => ServerStatus::WaitingForCode,
            "PENDING_VALIDATION" => ServerStatus::PendingValidation,
            _ => ServerStatus::Unknown,
        }
    }
}

/// Why an enrollment ended early. It also decides what `end_enrollment` reports.
enum Stop {
    Canceled,
    Denied,
    Failed(OnePasswordError),
}

impl From<OnePasswordError> for Stop {
    fn from(error: OnePasswordError) -> Stop {
        Stop::Failed(error)
    }
}

impl From<Stop> for OnePasswordError {
    fn from(stop: Stop) -> OnePasswordError {
        match stop {
            Stop::Canceled => OnePasswordError::Canceled,
            Stop::Denied => OnePasswordError::Denied,
            Stop::Failed(error) => error,
        }
    }
}

/// Enrolls this device and returns the credential bundle an enrolled device shared.
///
/// The context is closed with `end_enrollment` when this ends, unless the future is dropped first.
/// An enrollment that is canceled, from the UI or at the verification code prompt, or that fails
/// after the server handed out its uuid is also canceled on the server, so the approving device
/// stops waiting.
pub(super) async fn enroll_device(
    username: &str,
    sign_in_address: &str,
    sign_in_token: &str,
    ui: &dyn SsoUi,
    rest: &RestClient,
    timing: &Timing,
) -> Result<CredentialBundle, OnePasswordError> {
    let context = ui.begin_sso_enrollment().await;
    let context = &*context;
    let mut enrollment_uuid = None;

    // Checking the cancellation first makes it win a tie.
    let outcome = {
        let cancelled = pin!(context.cancelled());
        let enrollment = pin!(enroll(
            username,
            sign_in_address,
            sign_in_token,
            context,
            rest,
            timing,
            &mut enrollment_uuid,
        ));
        match select(cancelled, enrollment).await {
            Either::Left(_) => Err(Stop::Canceled),
            Either::Right((outcome, _)) => outcome,
        }
    };

    let result = match &outcome {
        Ok(_) => SsoEnrollmentResult::Success,
        Err(Stop::Canceled) => SsoEnrollmentResult::Canceled,
        Err(Stop::Denied) => SsoEnrollmentResult::Denied,
        Err(Stop::Failed(_)) => SsoEnrollmentResult::Failed,
    };

    // A denied enrollment is already over on the server.
    if matches!(outcome, Err(Stop::Canceled | Stop::Failed(_)))
        && let Some(enrollment_uuid) = &enrollment_uuid
    {
        cancel_enrollment(sign_in_token, enrollment_uuid, rest).await;
    }
    context.end_enrollment(result).await;

    outcome.map_err(OnePasswordError::from)
}

/// The steps of the enrollment. The uuid goes to `started` as soon as the server hands it out, for
/// the caller to cancel the enrollment should this be dropped halfway.
async fn enroll(
    username: &str,
    sign_in_address: &str,
    sign_in_token: &str,
    context: &dyn SsoEnrollmentContext,
    rest: &RestClient,
    timing: &Timing,
    started: &mut Option<String>,
) -> Result<CredentialBundle, Stop> {
    // Starting signals the enrolled devices to prepare for handing the credentials over.
    context
        .update_status(
            EnrollmentStatus::WaitingForApproval,
            "Waiting for approval from enrolled device...",
        )
        .await;
    let session = EnrollmentSession {
        username,
        sign_in_address,
        sign_in_token,
        enrollment_uuid: started.insert(start_enrollment(sign_in_token, rest).await?),
    };

    // The user has to press "Transfer key" on one of the enrolled devices.
    let status =
        poll_status_until_done(&[ServerStatus::SelectingVerifier], &session, rest, timing).await?;
    if valid_status(status)? != ServerStatus::WaitingForCode {
        return Err(unknown_status(status));
    }

    let mut replaced_msg_a = None;
    for attempt in 0..MAX_CODE_ATTEMPTS {
        let verification_code = ask_for_code(attempt, &session, context, rest, timing).await?;

        context
            .update_status(
                EnrollmentStatus::ExchangingCredentials,
                "Exchanging credentials securely",
            )
            .await;
        match perform_cpace(
            &session,
            &verification_code,
            replaced_msg_a.as_deref(),
            rest,
            timing,
        )
        .await?
        {
            Exchange::Shared(credential_bundle) => {
                context
                    .update_status(EnrollmentStatus::Completing, "Completing enrollment")
                    .await;
                return Ok(credential_bundle);
            }
            Exchange::WrongCode { msg_a } => replaced_msg_a = Some(msg_a),
        }
    }

    Err(Stop::Failed(OnePasswordError::VerificationCodeFailed))
}

/// Asks for the verification code the enrolled device shows. Polling on makes denying the request
/// there noticed while the user types.
async fn ask_for_code(
    attempt: u32,
    session: &EnrollmentSession<'_>,
    context: &dyn SsoEnrollmentContext,
    rest: &RestClient,
    timing: &Timing,
) -> Result<Zeroizing<String>, Stop> {
    let user_input = pin!(context.provide_verification_code(attempt));
    // After a wrong code the enrolled device checks it and shows a new one, so the status may be
    // any stage short of the end. 1Password's own client waits through all of them too.
    let poll = pin!(poll_status_until_done(
        &[
            ServerStatus::SelectingVerifier,
            ServerStatus::WaitingForCode,
            ServerStatus::PendingValidation,
        ],
        session,
        rest,
        timing,
    ));
    match select(user_input, poll).await {
        Either::Left((VerificationCodeResult::Code(code), _)) => Ok(Zeroizing::new(code)),
        Either::Left((VerificationCodeResult::Cancel, _)) => Err(Stop::Canceled),
        // Nothing but the user is supposed to end the wait.
        Either::Right((polled, _)) => Err(unknown_status(valid_status(polled?)?)),
    }
}

/// Denial ends the enrollment, any other status is up to the caller.
fn valid_status(status: ServerStatus) -> Result<ServerStatus, Stop> {
    match status {
        ServerStatus::Denied => Err(Stop::Denied),
        status => Ok(status),
    }
}

/// A status that nothing expects at this point.
fn unknown_status(status: ServerStatus) -> Stop {
    Stop::Failed(OnePasswordError::Internal(format!(
        "device enrollment failed with unknown status {status:?}"
    )))
}

/// Starts an enrollment and returns its uuid.
async fn start_enrollment(
    sign_in_token: &str,
    rest: &RestClient,
) -> Result<String, OnePasswordError> {
    let info: wire::SsoEnrollInfo = rest
        .post_json(
            "v3/device/enrollments",
            json!({ "signInToken": sign_in_token }),
        )
        .await?;

    Ok(info.enrollment_uuid)
}

/// Tells the server to drop the enrollment, so the enrolled devices stop waiting on it. Errors
/// are ignored: there is nothing left to do about them.
async fn cancel_enrollment(sign_in_token: &str, enrollment_uuid: &str, rest: &RestClient) {
    let _ = rest
        .delete_json(
            "v2/device/enrollments",
            json!({
                "enrollmentUuid": enrollment_uuid,
                "signInToken": sign_in_token,
            }),
        )
        .await;
}

/// Polls the status until it is one not in `ignore`.
async fn poll_status_until_done(
    ignore: &[ServerStatus],
    session: &EnrollmentSession<'_>,
    rest: &RestClient,
    timing: &Timing,
) -> Result<ServerStatus, OnePasswordError> {
    for _ in 0..timing.enrollment_poll_attempts() {
        let status = get_enrollment_status(session, rest).await?;
        if !ignore.contains(&status) {
            return Ok(status);
        }

        time::sleep(timing.enrollment_poll_interval).await;
    }

    Err(OnePasswordError::Internal(
        "device enrollment timed out".into(),
    ))
}

/// Reads the status of the enrollment.
async fn get_enrollment_status(
    session: &EnrollmentSession<'_>,
    rest: &RestClient,
) -> Result<ServerStatus, OnePasswordError> {
    // Denying the request makes the server answer 404, whatever the body.
    let response: Option<wire::SsoEnrollStatus> = rest
        .post_json_unless_status(
            "v3/device/enrollments/status",
            json!({
                "signInToken": session.sign_in_token,
                "enrollmentUuid": session.enrollment_uuid,
            }),
            StatusCode::NOT_FOUND,
        )
        .await?;

    Ok(response.map_or(ServerStatus::Denied, |response| {
        ServerStatus::parse(&response.status)
    }))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use data_encoding::{BASE64, BASE64URL_NOPAD};
    use serde_json::{Value, json};
    use tokio::sync::Notify;
    use wiremock::{Mock, MockBuilder, MockServer, Request, ResponseTemplate, matchers};

    use super::{
        super::{
            test_support::{
                CpaceVectors, SIGN_IN_TOKEN, mock_msga, path, quick_timing, rest_client, vectors,
            },
            ui::SsoLoginResult,
        },
        *,
    };

    /// What the user does at the verification code prompt.
    enum Prompt {
        Code(String),
        Cancel,
        /// Never answers, like a user who is still typing.
        Pending,
    }

    #[derive(Debug, PartialEq)]
    enum Event {
        Status(EnrollmentStatus, String),
        CodeAsked(u32),
        Ended(SsoEnrollmentResult),
    }

    fn status(status: EnrollmentStatus, message: &str) -> Event {
        Event::Status(status, message.into())
    }

    fn exchanging() -> Event {
        status(
            EnrollmentStatus::ExchangingCredentials,
            "Exchanging credentials securely",
        )
    }

    /// The handles the test keeps on a scripted enrollment.
    #[derive(Clone, Default)]
    struct Script {
        events: Arc<Mutex<Vec<Event>>>,
        cancel: Arc<Notify>,
    }

    impl Script {
        /// Makes `cancelled()` resolve, now or once it is asked for.
        fn cancel(&self) {
            self.cancel.notify_one();
        }

        fn take_events(&self) -> Vec<Event> {
            std::mem::take(&mut *self.events.lock().expect("not poisoned"))
        }
    }

    /// Answers the code prompts in turn.
    struct ScriptedContext {
        script: Script,
        prompts: Mutex<VecDeque<Prompt>>,
    }

    #[async_trait]
    impl SsoEnrollmentContext for ScriptedContext {
        async fn cancelled(&self) {
            self.script.cancel.notified().await;
        }

        async fn update_status(&self, status: EnrollmentStatus, message: &str) {
            self.script
                .events
                .lock()
                .expect("not poisoned")
                .push(Event::Status(status, message.into()));
        }

        async fn provide_verification_code(&self, attempt: u32) -> VerificationCodeResult {
            self.script
                .events
                .lock()
                .expect("not poisoned")
                .push(Event::CodeAsked(attempt));
            let prompt = self
                .prompts
                .lock()
                .expect("not poisoned")
                .pop_front()
                .expect("a scripted answer for every prompt");
            match prompt {
                Prompt::Code(code) => VerificationCodeResult::Code(code),
                Prompt::Cancel => VerificationCodeResult::Cancel,
                Prompt::Pending => std::future::pending().await,
            }
        }

        async fn end_enrollment(&self, result: SsoEnrollmentResult) {
            self.script
                .events
                .lock()
                .expect("not poisoned")
                .push(Event::Ended(result));
        }
    }

    /// A UI that hands out one scripted enrollment.
    struct ScriptedUi(Mutex<Option<ScriptedContext>>);

    #[async_trait]
    impl SsoUi for ScriptedUi {
        async fn perform_sso_login(&self, _: &str, _: &str) -> SsoLoginResult {
            unreachable!("the enrollment does not log in")
        }

        async fn begin_sso_enrollment(&self) -> Box<dyn SsoEnrollmentContext> {
            let context = self
                .0
                .lock()
                .expect("not poisoned")
                .take()
                .expect("one enrollment per UI");
            Box::new(context)
        }
    }

    fn scripted(prompt: Prompt) -> (ScriptedUi, Script) {
        scripted_prompts([prompt])
    }

    fn scripted_prompts(prompts: impl IntoIterator<Item = Prompt>) -> (ScriptedUi, Script) {
        let script = Script::default();
        let ui = ScriptedUi(Mutex::new(Some(ScriptedContext {
            script: script.clone(),
            prompts: Mutex::new(prompts.into_iter().collect()),
        })));
        (ui, script)
    }

    fn code(code: &str) -> Prompt {
        Prompt::Code(code.into())
    }

    async fn mock_start(server: &MockServer, vectors: &CpaceVectors) {
        server
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path("/api/v3/device/enrollments"))
                    .and(matchers::body_json(json!({"signInToken": SIGN_IN_TOKEN})))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "enrollmentUuid": vectors.enrollment_uuid,
                        "accountKeyUuid": "ACCOUNT_KEY_UUID",
                    })))
                    .expect(1),
            )
            .await;
    }

    fn status_mock(vectors: &CpaceVectors) -> MockBuilder {
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v3/device/enrollments/status"))
            .and(matchers::body_json(json!({
                "signInToken": SIGN_IN_TOKEN,
                "enrollmentUuid": vectors.enrollment_uuid,
            })))
    }

    fn reports(status: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({ "status": status }))
    }

    /// The body the server sends when the user denies the request on the enrolled device.
    fn denial() -> ResponseTemplate {
        ResponseTemplate::new(404).set_body_json(json!({}))
    }

    /// Answers the status requests in turn, then keeps repeating the last answer.
    async fn mock_statuses(
        server: &MockServer,
        vectors: &CpaceVectors,
        mut answers: Vec<ResponseTemplate>,
    ) {
        let last = answers.pop().expect("at least one answer");
        for answer in answers {
            server
                .register(status_mock(vectors).respond_with(answer).up_to_n_times(1))
                .await;
        }
        server
            .register(status_mock(vectors).respond_with(last))
            .await;
    }

    /// Expects `calls` requests to cancel the enrollment on the server.
    async fn mock_cancel(server: &MockServer, vectors: &CpaceVectors, calls: u64) {
        mock_cancel_answering(server, vectors, calls, ResponseTemplate::new(200)).await;
    }

    async fn mock_cancel_answering(
        server: &MockServer,
        vectors: &CpaceVectors,
        calls: u64,
        answer: ResponseTemplate,
    ) {
        server
            .register(
                Mock::given(matchers::method("DELETE"))
                    .and(matchers::path("/api/v2/device/enrollments"))
                    .and(matchers::body_json(json!({
                        "enrollmentUuid": vectors.enrollment_uuid,
                        "signInToken": SIGN_IN_TOKEN,
                    })))
                    .respond_with(answer)
                    .expect(calls),
            )
            .await;
    }

    async fn run_enrollment(
        server: &MockServer,
        vectors: &CpaceVectors,
        ui: &ScriptedUi,
        timing: &Timing,
    ) -> Result<CredentialBundle, OnePasswordError> {
        enroll_device(
            &vectors.username,
            &vectors.sign_in_address,
            SIGN_IN_TOKEN,
            ui,
            &rest_client(server),
            timing,
        )
        .await
    }

    fn assert_denied(result: Result<CredentialBundle, OnePasswordError>) {
        assert!(matches!(result.err(), Some(OnePasswordError::Denied)));
    }

    /// An enrolled device that refuses every code, for `rounds` exchanges. Each round has a
    /// `msga` of its own, which the server only serves after the replaced one once more, and a
    /// `taga` no client secret matches.
    async fn mock_refusing_enrolled_device(
        server: &MockServer,
        vectors: &CpaceVectors,
        rounds: u8,
    ) {
        let mut replaced = None;
        for round in 0..rounds {
            let mut msg_a: Value =
                serde_json::from_str(&vectors.msga_json).expect("the vector msga parses");
            msg_a["ad"]["session_id"] = json!(vec![round; 16]);
            let msg_a = BASE64.encode(msg_a.to_string().as_bytes());

            for served in replaced.iter().chain([&msg_a]) {
                server
                    .register(
                        Mock::given(matchers::method("POST"))
                            .and(matchers::path(path(vectors, "cpace/msga")))
                            .respond_with(
                                ResponseTemplate::new(200).set_body_json(json!({ "msga": served })),
                            )
                            .up_to_n_times(1)
                            .expect(1),
                    )
                    .await;
            }
            replaced = Some(msg_a);
        }

        for (method, endpoint, answer) in [
            ("PUT", "cpace/msgb", json!({"success": 1})),
            (
                "POST",
                "cpace/taga",
                json!({ "taga": BASE64URL_NOPAD.encode(&[7; 64]) }),
            ),
            ("PUT", "cpace/tagb", json!({"success": 1})),
        ] {
            server
                .register(
                    Mock::given(matchers::method(method))
                        .and(matchers::path(path(vectors, endpoint)))
                        .respond_with(ResponseTemplate::new(200).set_body_json(answer))
                        .expect(u64::from(rounds)),
                )
                .await;
        }
    }

    #[tokio::test]
    async fn three_wrong_codes_fail_the_enrollment() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(&server, &vectors, vec![reports("WAITING_FOR_CODE")]).await;
        mock_refusing_enrolled_device(&server, &vectors, 3).await;
        mock_cancel(&server, &vectors, 1).await;
        let (ui, script) =
            scripted_prompts([code("7777-XXXX"), code("8888-YYYY"), code("9999-ZZZZ")]);

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment fails");

        assert!(matches!(error, OnePasswordError::VerificationCodeFailed));
        assert_eq!(
            script.take_events(),
            [
                status(
                    EnrollmentStatus::WaitingForApproval,
                    "Waiting for approval from enrolled device..."
                ),
                Event::CodeAsked(0),
                exchanging(),
                Event::CodeAsked(1),
                exchanging(),
                Event::CodeAsked(2),
                exchanging(),
                Event::Ended(SsoEnrollmentResult::Failed),
            ]
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn canceling_after_a_wrong_code_cancels_the_enrollment_on_the_server() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(&server, &vectors, vec![reports("WAITING_FOR_CODE")]).await;
        mock_refusing_enrolled_device(&server, &vectors, 1).await;
        mock_cancel(&server, &vectors, 1).await;
        let (ui, script) = scripted_prompts([code("9999-ZZZZ"), Prompt::Cancel]);

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment is canceled");

        assert!(matches!(error, OnePasswordError::Canceled));
        assert_eq!(
            script.take_events(),
            [
                status(
                    EnrollmentStatus::WaitingForApproval,
                    "Waiting for approval from enrolled device..."
                ),
                Event::CodeAsked(0),
                exchanging(),
                Event::CodeAsked(1),
                Event::Ended(SsoEnrollmentResult::Canceled),
            ]
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn the_code_prompt_waits_through_the_stages_of_a_code_check() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(
            &server,
            &vectors,
            vec![
                reports("WAITING_FOR_CODE"),
                reports("PENDING_VALIDATION"),
                reports("SELECTING_VERIFIER"),
                reports("WAITING_FOR_CODE"),
                denial(),
            ],
        )
        .await;
        mock_cancel(&server, &vectors, 0).await;
        let (ui, script) = scripted(Prompt::Pending);

        let result = run_enrollment(&server, &vectors, &ui, &quick_timing()).await;

        assert_denied(result);
        assert_eq!(
            script.take_events().last(),
            Some(&Event::Ended(SsoEnrollmentResult::Denied))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn a_failed_exchange_fails_the_enrollment() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(&server, &vectors, vec![reports("WAITING_FOR_CODE")]).await;
        mock_msga(&server, &vectors).await;
        server
            .register(
                Mock::given(matchers::method("PUT"))
                    .and(matchers::path(path(&vectors, "cpace/msgb")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 0})))
                    .expect(1),
            )
            .await;
        mock_cancel(&server, &vectors, 1).await;
        let (ui, script) = scripted(code(&vectors.verification_code));

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment fails");

        assert!(matches!(
            &error,
            OnePasswordError::Internal(message) if message.contains("exchange credentials")
        ));
        assert_eq!(
            script.take_events(),
            [
                status(
                    EnrollmentStatus::WaitingForApproval,
                    "Waiting for approval from enrolled device..."
                ),
                Event::CodeAsked(0),
                exchanging(),
                Event::Ended(SsoEnrollmentResult::Failed),
            ]
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn denying_the_request_cancels_the_login() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(
            &server,
            &vectors,
            vec![reports("SELECTING_VERIFIER"), denial()],
        )
        .await;
        mock_cancel(&server, &vectors, 0).await;
        let (ui, script) = scripted(Prompt::Pending);

        let result = run_enrollment(&server, &vectors, &ui, &quick_timing()).await;

        assert_denied(result);
        assert_eq!(
            script.take_events(),
            [
                status(
                    EnrollmentStatus::WaitingForApproval,
                    "Waiting for approval from enrolled device..."
                ),
                Event::Ended(SsoEnrollmentResult::Denied),
            ]
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn only_the_status_decides_a_denial() {
        let vectors = vectors().cpace;
        for (response, denied) in [
            (
                ResponseTemplate::new(404)
                    .set_body_json(json!({"errorCode": 102, "errorMessage": "other"})),
                true,
            ),
            (
                ResponseTemplate::new(400)
                    .set_body_json(json!({"errorCode": 117, "errorMessage": "not found"})),
                false,
            ),
        ] {
            let server = MockServer::start().await;
            server
                .register(status_mock(&vectors).respond_with(response))
                .await;

            let status = get_enrollment_status(
                &EnrollmentSession {
                    username: &vectors.username,
                    sign_in_address: &vectors.sign_in_address,
                    sign_in_token: SIGN_IN_TOKEN,
                    enrollment_uuid: &vectors.enrollment_uuid,
                },
                &rest_client(&server),
            )
            .await;

            assert_eq!(status.ok() == Some(ServerStatus::Denied), denied);
        }
    }

    #[tokio::test]
    async fn a_not_found_error_body_is_a_denial_too() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(
            &server,
            &vectors,
            vec![
                ResponseTemplate::new(404)
                    .set_body_json(json!({"errorCode": 117, "errorMessage": "not found"})),
            ],
        )
        .await;
        let (ui, script) = scripted(Prompt::Pending);

        let result = run_enrollment(&server, &vectors, &ui, &quick_timing()).await;

        assert_denied(result);
        assert_eq!(
            script.take_events().last(),
            Some(&Event::Ended(SsoEnrollmentResult::Denied))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn denying_the_request_while_the_code_is_typed_is_a_denial() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(
            &server,
            &vectors,
            vec![reports("WAITING_FOR_CODE"), denial()],
        )
        .await;
        mock_cancel(&server, &vectors, 0).await;
        let (ui, script) = scripted(Prompt::Pending);

        let result = run_enrollment(&server, &vectors, &ui, &quick_timing()).await;

        assert_denied(result);
        assert_eq!(
            script.take_events().last(),
            Some(&Event::Ended(SsoEnrollmentResult::Denied))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn polling_times_out() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        server
            .register(
                status_mock(&vectors)
                    .respond_with(reports("SELECTING_VERIFIER"))
                    .expect(5),
            )
            .await;
        mock_cancel(&server, &vectors, 1).await;
        let (ui, script) = scripted(Prompt::Pending);
        let timing = Timing {
            enrollment_poll_timeout: Duration::from_millis(5),
            ..quick_timing()
        };

        let error = run_enrollment(&server, &vectors, &ui, &timing)
            .await
            .err()
            .expect("the enrollment fails");

        assert!(matches!(
            &error,
            OnePasswordError::Internal(message) if message.contains("timed out")
        ));
        assert_eq!(
            script.take_events().last(),
            Some(&Event::Ended(SsoEnrollmentResult::Failed))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn canceling_while_polling_cancels_the_enrollment_on_the_server() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        let (ui, script) = scripted(Prompt::Pending);
        let canceler = script.clone();
        server
            .register(status_mock(&vectors).respond_with(move |_: &Request| {
                canceler.cancel();
                reports("SELECTING_VERIFIER")
            }))
            .await;
        mock_cancel(&server, &vectors, 1).await;

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment is canceled");

        assert!(matches!(error, OnePasswordError::Canceled));
        assert_eq!(
            script.take_events(),
            [
                status(
                    EnrollmentStatus::WaitingForApproval,
                    "Waiting for approval from enrolled device..."
                ),
                Event::Ended(SsoEnrollmentResult::Canceled),
            ]
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn canceling_before_the_server_knows_the_enrollment_sends_nothing() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        let (ui, script) = scripted(Prompt::Pending);
        script.cancel();

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment is canceled");

        assert!(matches!(error, OnePasswordError::Canceled));
        assert_eq!(
            script.take_events(),
            [Event::Ended(SsoEnrollmentResult::Canceled)]
        );
        assert!(
            server
                .received_requests()
                .await
                .expect("requests are recorded")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn canceling_at_the_code_prompt_cancels_the_enrollment_on_the_server() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(&server, &vectors, vec![reports("WAITING_FOR_CODE")]).await;
        mock_cancel(&server, &vectors, 1).await;
        let (ui, script) = scripted(Prompt::Cancel);

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment is canceled");

        assert!(matches!(error, OnePasswordError::Canceled));
        assert_eq!(
            script.take_events(),
            [
                status(
                    EnrollmentStatus::WaitingForApproval,
                    "Waiting for approval from enrolled device..."
                ),
                Event::CodeAsked(0),
                Event::Ended(SsoEnrollmentResult::Canceled),
            ]
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn a_failing_server_cancellation_is_ignored() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(&server, &vectors, vec![reports("WAITING_FOR_CODE")]).await;
        mock_cancel_answering(&server, &vectors, 1, ResponseTemplate::new(500)).await;
        let (ui, script) = scripted(Prompt::Cancel);

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment is canceled");

        assert!(matches!(error, OnePasswordError::Canceled));
        assert_eq!(
            script.take_events().last(),
            Some(&Event::Ended(SsoEnrollmentResult::Canceled))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn the_poll_ending_before_the_code_arrives_fails_the_enrollment() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(
            &server,
            &vectors,
            vec![reports("WAITING_FOR_CODE"), reports("SOMETHING_NEW")],
        )
        .await;
        mock_cancel(&server, &vectors, 1).await;
        let (ui, script) = scripted(Prompt::Pending);

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment fails");

        assert!(matches!(
            &error,
            OnePasswordError::Internal(message) if message.contains("unknown status Unknown")
        ));
        assert_eq!(
            script.take_events().last(),
            Some(&Event::Ended(SsoEnrollmentResult::Failed))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn an_unexpected_status_after_the_approval_wait_fails_the_enrollment() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_start(&server, &vectors).await;
        mock_statuses(&server, &vectors, vec![reports("SOMETHING_NEW")]).await;
        let (ui, script) = scripted(Prompt::Pending);

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment fails");

        assert!(matches!(
            &error,
            OnePasswordError::Internal(message) if message.contains("unknown status Unknown")
        ));
        assert_eq!(
            script.take_events().last(),
            Some(&Event::Ended(SsoEnrollmentResult::Failed))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn a_failing_start_fails_the_enrollment() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v3/device/enrollments"))
                    .respond_with(ResponseTemplate::new(503))
                    .expect(1),
            )
            .await;
        mock_cancel(&server, &vectors, 0).await;
        let (ui, script) = scripted(Prompt::Pending);

        let error = run_enrollment(&server, &vectors, &ui, &quick_timing())
            .await
            .err()
            .expect("the enrollment fails");

        assert!(matches!(
            error,
            OnePasswordError::UnexpectedStatus { status: 503, .. }
        ));
        assert_eq!(
            script.take_events(),
            [
                status(
                    EnrollmentStatus::WaitingForApproval,
                    "Waiting for approval from enrolled device..."
                ),
                Event::Ended(SsoEnrollmentResult::Failed),
            ]
        );
        server.verify().await;
    }

    #[test]
    fn parses_server_statuses() {
        assert_eq!(
            ServerStatus::parse("SELECTING_VERIFIER"),
            ServerStatus::SelectingVerifier
        );
        assert_eq!(
            ServerStatus::parse("WAITING_FOR_CODE"),
            ServerStatus::WaitingForCode
        );
        assert_eq!(
            ServerStatus::parse("PENDING_VALIDATION"),
            ServerStatus::PendingValidation
        );
        assert_eq!(ServerStatus::parse("DONE"), ServerStatus::Unknown);
        assert_eq!(ServerStatus::parse(""), ServerStatus::Unknown);
    }

    #[test]
    fn a_zero_poll_interval_never_polls() {
        let timing = Timing {
            enrollment_poll_interval: Duration::ZERO,
            ..quick_timing()
        };

        assert_eq!(timing.enrollment_poll_attempts(), 0);
        assert_eq!(Timing::default().enrollment_poll_attempts(), 150);
    }

    #[test]
    fn the_enrollment_can_run_on_another_thread() {
        fn assert_send(_: &impl Send) {}

        let vectors = vectors().cpace;
        let rest = RestClient::new(
            reqwest::Client::new(),
            "http://localhost",
            "client",
            "user agent",
            "op user agent",
        )
        .expect("valid headers");
        let (ui, _) = scripted(Prompt::Pending);
        let timing = quick_timing();

        let enrollment = enroll_device(
            &vectors.username,
            &vectors.sign_in_address,
            SIGN_IN_TOKEN,
            &ui,
            &rest,
            &timing,
        );

        assert_send(&enrollment);
    }
}
