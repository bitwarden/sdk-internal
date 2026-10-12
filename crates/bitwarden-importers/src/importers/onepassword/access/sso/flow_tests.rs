//! The whole SSO login against a fake server: what it asks of the identity provider and of the
//! server.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitwarden_api_base::new_http_client;
use serde_json::json;
use wiremock::{Mock, ResponseTemplate, matchers};
use zeroize::Zeroizing;

use super::{
    super::{
        client::{Client, MasterKey, download_vaults},
        credentials::SsoCredentials,
        error::OnePasswordError,
        session::Session,
        sign_in::{SignInAddress, SignInDomain},
    },
    fake_server::{
        FakeServer, REDIRECTED_TO, SSO_LOGIN_URL, SSO_SESSION_UUID, USERNAME, account_unlock_key,
        client_info, verify_response,
    },
    sso_login,
    test_support::{SIGN_IN_TOKEN, mock_enrolled_device_for_any_client, quick_timing, vectors},
    ui::{
        EnrollmentStatus, SsoEnrollmentContext, SsoEnrollmentResult, SsoLoginResult, SsoUi,
        VerificationCodeResult,
    },
};

/// The user of the login: signs in with the identity provider or gives up on it, and enters the
/// verification code of the vectors when the device is enrolled.
struct ScriptedUser {
    login: Mutex<Option<SsoLoginResult>>,
    enrollments: Arc<Mutex<Vec<SsoEnrollmentResult>>>,
}

impl ScriptedUser {
    fn signing_in() -> ScriptedUser {
        ScriptedUser::new(SsoLoginResult::RedirectedTo(REDIRECTED_TO.into()))
    }

    fn giving_up() -> ScriptedUser {
        ScriptedUser::new(SsoLoginResult::Cancel)
    }

    fn new(login: SsoLoginResult) -> ScriptedUser {
        ScriptedUser {
            login: Mutex::new(Some(login)),
            enrollments: Arc::default(),
        }
    }

    /// How the enrollments that ran ended.
    fn enrollments(&self) -> Vec<SsoEnrollmentResult> {
        self.enrollments.lock().expect("not poisoned").clone()
    }
}

#[async_trait]
impl SsoUi for ScriptedUser {
    async fn perform_sso_login(&self, sso_login_url: &str, redirect_to: &str) -> SsoLoginResult {
        assert_eq!(sso_login_url, SSO_LOGIN_URL);
        assert_eq!(redirect_to, "https://acme.1password.com/sso/oidc/redirect/");
        self.login
            .lock()
            .expect("not poisoned")
            .take()
            .expect("the identity provider is asked once")
    }

    async fn begin_sso_enrollment(&self) -> Box<dyn SsoEnrollmentContext> {
        Box::new(EnrollingUser {
            ended: self.enrollments.clone(),
        })
    }
}

struct EnrollingUser {
    ended: Arc<Mutex<Vec<SsoEnrollmentResult>>>,
}

#[async_trait]
impl SsoEnrollmentContext for EnrollingUser {
    async fn cancelled(&self) {
        std::future::pending().await
    }

    async fn update_status(&self, _: EnrollmentStatus, _: &str) {}

    async fn provide_verification_code(&self) -> VerificationCodeResult {
        VerificationCodeResult::Code(vectors().cpace.verification_code)
    }

    async fn end_enrollment(&self, result: SsoEnrollmentResult) {
        self.ended.lock().expect("not poisoned").push(result);
    }
}

fn credentials() -> SsoCredentials {
    SsoCredentials {
        username: USERNAME.into(),
        sign_in_address: SignInAddress {
            subdomain: "acme".into(),
            domain: SignInDomain::Global,
        },
    }
}

async fn sign_in(
    server: &FakeServer,
    ui: &ScriptedUser,
) -> Result<(Session, Zeroizing<Vec<u8>>), OnePasswordError> {
    sso_login(
        &credentials(),
        &client_info(),
        ui,
        &server.rest(),
        &quick_timing(),
    )
    .await
}

/// What the server needs to enroll a device: the enrollment, the approval of an enrolled device
/// and the credential exchange with it.
async fn mock_enrollment(server: &FakeServer) {
    let cpace = vectors().cpace;
    server
        .mock
        .register(
            Mock::given(matchers::method("POST"))
                .and(matchers::path("/api/v3/device/enrollments"))
                .and(matchers::header("x-agilebits-session-id", SSO_SESSION_UUID))
                .and(matchers::body_json(json!({"signInToken": SIGN_IN_TOKEN})))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "enrollmentUuid": cpace.enrollment_uuid,
                })))
                .expect(1),
        )
        .await;
    server
        .mock
        .register(
            Mock::given(matchers::method("POST"))
                .and(matchers::path("/api/v3/device/enrollments/status"))
                .and(matchers::header("x-agilebits-session-id", SSO_SESSION_UUID))
                .and(matchers::body_json(json!({
                    "signInToken": SIGN_IN_TOKEN,
                    "enrollmentUuid": cpace.enrollment_uuid,
                })))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"status": "WAITING_FOR_CODE"})),
                ),
        )
        .await;
    mock_enrolled_device_for_any_client(&server.mock, &cpace, &server.sign_in_address()).await;
}

/// Downloads the account with the account unlock key and checks it has what the server holds.
async fn assert_downloads_the_account(session: Session, master_key: Zeroizing<Vec<u8>>) {
    assert_eq!(*master_key, account_unlock_key());

    let account = download_vaults(MasterKey::Known(master_key), &session)
        .await
        .expect("the keysets open with the account unlock key");

    assert!(account.skipped_vaults.is_empty());
    let [vault] = account.vaults.as_slice() else {
        panic!("expected one vault, got {}", account.vaults.len());
    };
    assert_eq!(vault.name, "Personal");
    assert!(vault.skipped_items.is_empty());
    let [item] = vault.items.as_slice() else {
        panic!("expected one item, got {}", vault.items.len());
    };
    assert_eq!(item.overview.title.as_deref(), Some("Example"));
}

#[tokio::test]
async fn a_new_device_is_enrolled_and_signs_in() {
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    server.mock_sso_start().await;
    server
        .mock_sso_verify(verify_response("device_not_enrolled"))
        .await;
    mock_enrollment(&server).await;
    let ui = ScriptedUser::signing_in();

    let (session, master_key) = sign_in(&server, &ui)
        .await
        .expect("the device is enrolled and signs in");

    assert_downloads_the_account(session, master_key).await;
    assert_eq!(ui.enrollments(), [SsoEnrollmentResult::Success]);
    assert!(
        !server
            .requested_paths()
            .await
            .iter()
            .any(|path| path.contains("devicecredentials"))
    );
    server.mock.verify().await;
}

#[tokio::test]
async fn a_second_factor_after_the_sso_login_is_unsupported() {
    let server = FakeServer::start_with_mfa(json!({"totp": {"enabled": true}})).await;
    server.mock_login_info(true).await;
    server.mock_sso_start().await;
    server
        .mock_sso_verify(verify_response("device_not_enrolled"))
        .await;
    mock_enrollment(&server).await;
    let ui = ScriptedUser::signing_in();

    let error = sign_in(&server, &ui).await.err();

    assert!(
        matches!(&error, Some(OnePasswordError::Unsupported(what)) if what.contains("two-factor")),
        "unexpected result: {error:?}"
    );
}

#[tokio::test]
async fn giving_up_at_the_identity_provider_cancels_the_login() {
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    server.mock_sso_start().await;
    let ui = ScriptedUser::giving_up();

    let error = sign_in(&server, &ui).await.err();

    assert!(
        matches!(&error, Some(OnePasswordError::Canceled)),
        "unexpected result: {error:?}"
    );
    assert_eq!(
        server.requested_paths().await,
        ["/api/v2/auth/methods", "/api/v3/auth/sso/oidc/start"]
    );
    assert!(ui.enrollments().is_empty());
    server.mock.verify().await;
}

#[tokio::test]
async fn an_account_without_the_sso_method_is_unsupported() {
    let server = FakeServer::start().await;
    server.mock_login_info(false).await;
    let ui = ScriptedUser::signing_in();

    let error = sign_in(&server, &ui).await.err();

    assert!(
        matches!(&error, Some(OnePasswordError::Unsupported(what)) if what.contains(USERNAME)),
        "unexpected result: {error:?}"
    );
    assert_eq!(server.requested_paths().await, ["/api/v2/auth/methods"]);
    server.mock.verify().await;
}

#[tokio::test]
async fn opening_an_account_checks_the_credentials_before_any_request() {
    let client = Client::new(new_http_client());
    let ui = ScriptedUser::giving_up();

    let mut blank_username = credentials();
    blank_username.username = " ".into();
    let mut bad_address = credentials();
    bad_address.sign_in_address.subdomain = "evil.com/x".into();

    for (credentials, expected) in [
        (blank_username, "username"),
        (bad_address, "sign-in address"),
    ] {
        let error = client.open_account_sso(credentials, &ui).await.err();

        assert!(
            matches!(&error, Some(error) if error.to_string().contains(expected)),
            "unexpected result: {error:?}"
        );
    }
}

/// An import runs the login on a task of its own.
#[test]
fn the_login_can_run_on_another_thread() {
    fn assert_send<T: Send>(_: &T) {}

    let client = Client::new(new_http_client());
    let ui = ScriptedUser::giving_up();

    assert_send(&client.open_account_sso(credentials(), &ui));
}
