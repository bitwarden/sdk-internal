//! Login with single sign-on: enroll this device with the approval of an enrolled one, then sign in
//! with the credentials it hands over.

use std::time::Duration;

use serde_json::json;
use url::{Url, form_urlencoded};
use zeroize::Zeroizing;

use self::{
    enrollment::enroll_device,
    ui::{SsoLoginResult, SsoUi},
};
use super::{
    credentials::SsoCredentials,
    device::ClientInfo,
    error::OnePasswordError,
    login::{AUTH_COMPLETE_ENDPOINT, AUTH_START_ENDPOINT, SignInMethods, fetch_auth_methods},
    mac::MacSigner,
    opdata::{AesKey, decode64_loose},
    rest::RestClient,
    session::Session,
    srp::perform_and_verify_with_x,
    wire::{AuthComplete, LoginInfo, NewSession, SsoLoginUrl, SsoSession},
};

mod cpace;
mod enrollment;
#[cfg(test)]
mod test_support;
pub mod ui;

const SSO_START_ENDPOINT: &str = "v3/auth/sso/oidc/start";
const SSO_VERIFY_ENDPOINT: &str = "v3/auth/sso/oidc/verify";
const DEVICE_NOT_ENROLLED: &str = "device_not_enrolled";

/// The timing knobs of the SSO network flows, grouped so the tests can shrink them.
pub(super) struct Timing {
    /// Delay before retrying a request of `post_json_until_result`, which the server answered
    /// with 200 and an empty body.
    pub(super) until_result_delay: Duration,
    /// Maximum number of attempts of such a request before it fails.
    pub(super) until_result_attempts: u32,
    /// Delay between two polls of the enrollment status. The 1Password web client polls every
    /// 2 seconds.
    pub(super) enrollment_poll_interval: Duration,
    /// How long the enrollment status is polled before the enrollment times out.
    pub(super) enrollment_poll_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            until_result_delay: Duration::from_millis(500),
            until_result_attempts: 20,
            enrollment_poll_interval: Duration::from_secs(2),
            enrollment_poll_timeout: Duration::from_secs(5 * 60),
        }
    }
}

/// Signs in with single sign-on. Returns the signed session and the account unlock key that opens
/// the account's keysets.
///
/// The device is always new to the account, so the user approves it on an enrolled device through
/// `ui`.
pub(super) async fn sso_login(
    credentials: &SsoCredentials,
    client_info: &ClientInfo,
    ui: &dyn SsoUi,
    rest: &RestClient,
    timing: &Timing,
) -> Result<(Session, Zeroizing<Vec<u8>>), OnePasswordError> {
    // 1. Get the login info to find out if SSO is available and where its API is.
    let login_info = fetch_auth_methods(&credentials.username, rest).await?;

    // 2. Refuse an account that does not sign in with SSO.
    let account = require_sso(&login_info, &credentials.username)?;

    // 3. From here on the requests go to the SSO API of the account.
    let sso_rest = rest.with_base_url(account.api_url());

    // 4. The server names the identity provider page to send the user to.
    let sso_login_url = start_sso_login(&account, &sso_rest).await?;

    // 5. The user signs in at the identity provider, which redirects back with a code.
    let (code, state) = perform_sso_login(&sso_login_url, ui).await?;

    // 6. The server trades the code for an SSO session and a sign-in token.
    let sso_session = verify_sso_login(&code, &state, client_info, &sso_rest).await?;

    // 7. The requests that follow belong to this SSO session.
    let sso_rest = sso_rest.with_session_id(&sso_session.user.session_uuid)?;

    // 8. The server has not seen this device.
    require_new_device(&sso_session)?;

    // 9. The user approves the device on an enrolled one, which hands over the credential bundle.
    let sign_in_token = sso_session.sso_auth.sign_in_token_details.token.as_str();
    let bundle = enroll_device(
        &credentials.username,
        &account.sign_in_address,
        sign_in_token,
        ui,
        &sso_rest,
        timing,
    )
    .await?;

    // 10. The bundle holds the SRP x that signs in without a password.
    let srp_x = Zeroizing::new(decode64_loose(&bundle.srpx)?);
    let master_key = Zeroizing::new(decode64_loose(&bundle.auk.k)?);
    let (session_key, session_rest) = login(
        &credentials.username,
        &account,
        client_info,
        &sso_session,
        &srp_x,
        &sso_rest,
    )
    .await?;

    // 11. The account unlock key plays the role of the master key.
    Ok((Session::new(session_key, session_rest), master_key))
}

/// What an SSO login needs from the login info of the account.
pub(super) struct SsoAccount {
    pub(super) user_uuid: String,
    /// The address the SSO endpoints are at, as the server sent it. The enrollment key exchange
    /// hashes it verbatim.
    pub(super) sign_in_address: String,
}

impl SsoAccount {
    /// The root of the SSO API.
    pub(super) fn api_url(&self) -> String {
        format!("{}/api", self.sign_in_address.trim_end_matches('/'))
    }
}

/// Checks that the account signs in with SSO and that its login info says who the user is and
/// where the SSO endpoints are.
pub(super) fn require_sso(
    login_info: &LoginInfo,
    username: &str,
) -> Result<SsoAccount, OnePasswordError> {
    if !SignInMethods::of(login_info).sso {
        return Err(OnePasswordError::Unsupported(format!(
            "no SSO login method found for account {username}"
        )));
    }

    let (Some(user_uuid), Some(sign_in_address)) = (
        non_empty(&login_info.user_uuid),
        non_empty(&login_info.sign_in_address),
    ) else {
        return Err(OnePasswordError::Internal(
            "SSO login info is missing userUuid or signInAddress".into(),
        ));
    };
    validate_sign_in_address(sign_in_address)?;

    Ok(SsoAccount {
        user_uuid: user_uuid.to_string(),
        sign_in_address: sign_in_address.to_string(),
    })
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.is_empty())
}

/// The server picks this address and every SSO request goes to it, so it has to be a plain https
/// address the API path can be appended to. The address is not echoed in the error: it can carry
/// credentials.
fn validate_sign_in_address(address: &str) -> Result<(), OnePasswordError> {
    let valid = Url::parse(address).is_ok_and(|url| {
        has_allowed_scheme(&url)
            && url.has_host()
            && url.query().is_none()
            && url.fragment().is_none()
    });
    if !valid {
        return Err(OnePasswordError::Internal(
            "the SSO sign-in address is not an https URL".into(),
        ));
    }
    Ok(())
}

/// Requests to a server supplied URL carry credentials and the user opens one in a browser, so
/// only https will do. The fake servers of the tests have no TLS, hence http under test.
fn has_allowed_scheme(url: &Url) -> bool {
    url.scheme() == "https" || (cfg!(test) && url.scheme() == "http")
}

fn is_web_url(url: &str) -> bool {
    Url::parse(url).is_ok_and(|url| has_allowed_scheme(&url) && url.has_host())
}

/// Asks for the URL of the identity provider login.
pub(super) async fn start_sso_login(
    account: &SsoAccount,
    rest: &RestClient,
) -> Result<String, OnePasswordError> {
    let response: SsoLoginUrl = rest
        .post_json(SSO_START_ENDPOINT, json!({ "userUuid": account.user_uuid }))
        .await?;
    Ok(response.auth_redirect)
}

/// Has the user log in with the identity provider, and returns the authorization code and the
/// state it redirects back with.
pub(super) async fn perform_sso_login(
    sso_login_url: &str,
    ui: &dyn SsoUi,
) -> Result<(String, String), OnePasswordError> {
    // Neither URL is echoed in the errors: they carry the state.
    if !is_web_url(sso_login_url) {
        return Err(OnePasswordError::Internal(
            "the SSO login URL is not an https URL".into(),
        ));
    }

    let redirect_to = url_parameter(sso_login_url, "redirect_uri").ok_or_else(|| {
        OnePasswordError::Internal("no redirect_uri found in the SSO login URL".into())
    })?;
    if !is_web_url(&redirect_to) {
        return Err(OnePasswordError::Internal(
            "the SSO redirect URI is not an https URL".into(),
        ));
    }

    let redirected_to = match ui.perform_sso_login(sso_login_url, &redirect_to).await {
        SsoLoginResult::RedirectedTo(url) => url,
        SsoLoginResult::Cancel => return Err(OnePasswordError::Canceled),
    };

    // The URL is not echoed in the errors: it carries the authorization code.
    let code = url_parameter(&redirected_to, "code").ok_or_else(|| {
        OnePasswordError::Internal("no code returned from the SSO provider".into())
    })?;
    let state = url_parameter(&redirected_to, "state").ok_or_else(|| {
        OnePasswordError::Internal("no state returned from the SSO provider".into())
    })?;
    Ok((code, state))
}

/// Exchanges the authorization code for an SSO session.
pub(super) async fn verify_sso_login(
    code: &str,
    state: &str,
    client_info: &ClientInfo,
    rest: &RestClient,
) -> Result<SsoSession, OnePasswordError> {
    rest.post_json(
        SSO_VERIFY_ENDPOINT,
        json!({
            "code": code,
            "state": state,
            "device": client_info.sso_verify_device_body(),
        }),
    )
    .await
}

/// A device with a fresh id cannot be known to the server, so anything but `device_not_enrolled`
/// is unexpected.
pub(super) fn require_new_device(session: &SsoSession) -> Result<(), OnePasswordError> {
    if session.state != DEVICE_NOT_ENROLLED {
        return Err(OnePasswordError::Internal(format!(
            "unexpected SSO session state: {}",
            session.state
        )));
    }
    Ok(())
}

/// Signs in with the sign-in token the SSO login earned, proving knowledge of the SRP x from the
/// credential bundle. Returns the session key and a client that signs its requests with it.
///
/// Fails with `Unsupported` when the server asks for a second factor.
async fn login(
    username: &str,
    account: &SsoAccount,
    client_info: &ClientInfo,
    sso_session: &SsoSession,
    srp_x: &[u8],
    rest: &RestClient,
) -> Result<(AesKey, RestClient), OnePasswordError> {
    let sign_in_token = sso_session.sso_auth.sign_in_token_details.token.as_str();

    // 1. Start a new session. The session id of the SSO login stays in use.
    let started = start_auth(
        sign_in_token,
        &client_info.device_uuid,
        &account.user_uuid,
        rest,
    )
    .await?;
    let (Some(key_uuid), Some(auth)) = (started.key_uuid, started.auth) else {
        return Err(OnePasswordError::Internal(format!(
            "missing SRP parameters in the start response, its status is '{}'",
            started.status
        )));
    };

    // 2. Do the regular SRP exchange with the x from the bundle. Only the salt of the parameters is
    //    needed, as nothing is derived from a password.
    let session_key = perform_and_verify_with_x(
        srp_x,
        username,
        &key_uuid,
        &decode64_loose(&auth.salt)?,
        &sso_session.user.session_uuid,
        rest,
    )
    .await?;

    // 3. Sign the following requests with the session key, counting them from 1.
    let signed_rest = rest.with_signer(MacSigner::with_request_id(&session_key, 1));

    // 4. Tell the server which device this is. It may answer by asking for a second factor.
    complete_auth(client_info, sign_in_token, &session_key, &signed_rest).await?;

    Ok((session_key, signed_rest))
}

async fn start_auth(
    sign_in_token: &str,
    device_uuid: &str,
    user_uuid: &str,
    rest: &RestClient,
) -> Result<NewSession, OnePasswordError> {
    rest.post_json(
        AUTH_START_ENDPOINT,
        json!({
            "signInToken": sign_in_token,
            "deviceUuid": device_uuid,
            "userUuid": user_uuid,
        }),
    )
    .await
}

async fn complete_auth(
    client_info: &ClientInfo,
    sign_in_token: &str,
    session_key: &AesKey,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let response: AuthComplete = rest
        .post_encrypted_json(
            AUTH_COMPLETE_ENDPOINT,
            json!({
                "client": client_info.client_id(),
                "signInToken": sign_in_token,
                "device": client_info.sso_complete_device_body(),
            }),
            session_key,
        )
        .await?;

    if response.mfa.is_some() {
        return Err(OnePasswordError::Unsupported(
            "two-factor authentication after SSO is not supported".into(),
        ));
    }
    Ok(())
}

/// The form-decoded value of the first parameter called `name` in the query or the fragment of
/// `url`, as OAuth encodes the redirect. A missing or empty value is `None`.
fn url_parameter(url: &str, name: &str) -> Option<String> {
    let (url, fragment) = url.split_once('#').unwrap_or((url, ""));
    let query = url.split_once('?').map_or("", |(_, query)| query);

    [query, fragment]
        .into_iter()
        .flat_map(|part| form_urlencoded::parse(part.as_bytes()))
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use serde_json::{Value, json};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::{
        test_support::{SIGN_IN_TOKEN, rest_client, vectors},
        ui::SsoEnrollmentContext,
        *,
    };

    const LOGIN_URL: &str = "https://idp.example.com/authorize?client_id=abc&response_type=code\
        &redirect_uri=https%3A%2F%2Facme.1password.com%2Fsso%2Foidc%2Fredirect%2F&scope=openid";
    const REDIRECT_TO: &str = "https://acme.1password.com/sso/oidc/redirect/";

    /// Plays the identity provider step, and records what it was asked to open.
    struct ScriptedUi {
        result: Mutex<Option<SsoLoginResult>>,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl ScriptedUi {
        fn new(result: SsoLoginResult) -> ScriptedUi {
            ScriptedUi {
                result: Mutex::new(Some(result)),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn redirected_to(url: &str) -> ScriptedUi {
            ScriptedUi::new(SsoLoginResult::RedirectedTo(url.into()))
        }

        fn calls(&self) -> Vec<(String, String)> {
            self.calls.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait]
    impl SsoUi for ScriptedUi {
        async fn perform_sso_login(
            &self,
            sso_login_url: &str,
            redirect_to: &str,
        ) -> SsoLoginResult {
            self.calls
                .lock()
                .expect("not poisoned")
                .push((sso_login_url.into(), redirect_to.into()));
            self.result
                .lock()
                .expect("not poisoned")
                .take()
                .expect("the login runs once")
        }

        async fn begin_sso_enrollment(&self) -> Box<dyn SsoEnrollmentContext> {
            unreachable!("the login steps never enroll")
        }
    }

    fn login_info(user_uuid: Option<&str>, sign_in_address: Option<&str>) -> LoginInfo {
        serde_json::from_value(json!({
            "userUuid": user_uuid,
            "signInAddress": sign_in_address,
            "authMethods": [
                {"type": "PASSWORD+SK"},
                {"type": "OIDC", "provider": "Acme", "iconUrl": null},
            ],
        }))
        .expect("valid login info")
    }

    fn sso_account() -> SsoAccount {
        require_sso(
            &login_info(Some("USERUUID"), Some("https://acme.1password.com")),
            "user@example.com",
        )
        .expect("an SSO account")
    }

    fn client_info() -> ClientInfo {
        ClientInfo::for_desktop("device-uuid")
    }

    /// What `v3/auth/sso/oidc/verify` answers, `state` being what the server says about the device.
    fn verify_response(state: &str) -> Value {
        json!({
            "type": state,
            "user": {
                "sessionUuid": "SESSIONUUID",
                "accountUuid": "ACCOUNTUUID",
                "userUuid": "USERUUID",
                "email": "user@example.com",
            },
            "ssoAuth": {
                "signInTokenDetails": {
                    "token": SIGN_IN_TOKEN,
                    "publicKey": "PUBLICKEY",
                    "exp": "2030-01-01T00:00:00Z",
                },
            },
        })
    }

    fn session(state: &str) -> SsoSession {
        serde_json::from_value(verify_response(state)).expect("a valid session")
    }

    #[test]
    fn requires_the_oidc_method() {
        let mut info = login_info(Some("USERUUID"), Some("https://acme.1password.com"));
        info.auth_methods.retain(|method| method.kind != "OIDC");

        let error = require_sso(&info, "user@example.com").err();

        assert!(
            matches!(&error, Some(OnePasswordError::Unsupported(what)) if what.contains("user@example.com")),
            "unexpected result: {error:?}"
        );
    }

    #[test]
    fn requires_the_user_uuid_and_the_sign_in_address() {
        for (user_uuid, sign_in_address) in [
            (None, Some("https://acme.1password.com")),
            (Some(""), Some("https://acme.1password.com")),
            (Some("USERUUID"), None),
            (Some("USERUUID"), Some("")),
            (None, None),
        ] {
            let error =
                require_sso(&login_info(user_uuid, sign_in_address), "user@example.com").err();

            assert!(
                matches!(error, Some(OnePasswordError::Internal(_))),
                "unexpected result for {user_uuid:?} and {sign_in_address:?}: {error:?}"
            );
        }
    }

    #[test]
    fn accepts_the_login_info_of_an_sso_account() {
        let account = sso_account();

        assert_eq!(account.user_uuid, "USERUUID");
        assert_eq!(account.sign_in_address, "https://acme.1password.com");
        assert_eq!(account.api_url(), "https://acme.1password.com/api");
    }

    #[test]
    fn a_trailing_slash_is_not_doubled_in_the_api_url() {
        let account = require_sso(
            &login_info(Some("USERUUID"), Some("https://acme.1password.com/")),
            "user@example.com",
        )
        .expect("an SSO account");

        assert_eq!(account.sign_in_address, "https://acme.1password.com/");
        assert_eq!(account.api_url(), "https://acme.1password.com/api");
    }

    #[test]
    fn accepts_the_address_forms_of_a_web_server() {
        for address in [
            "https://acme.1password.com",
            "https://acme.1password.com/",
            "http://127.0.0.1:8080",
            "https://sso.example.com:8443/base",
        ] {
            require_sso(
                &login_info(Some("USERUUID"), Some(address)),
                "user@example.com",
            )
            .unwrap_or_else(|error| panic!("'{address}' is rejected: {error}"));
        }
    }

    #[test]
    fn rejects_a_sign_in_address_that_is_not_a_web_address() {
        for address in [
            "acme.1password.com",
            "//acme.1password.com",
            "/api",
            "ftp://acme.1password.com",
            "file://acme.1password.com/api",
            "javascript:alert(1)",
            "mailto:user@example.com",
            "https://",
            "https://acme.1password.com?next=/",
            "https://acme.1password.com/?",
            "https://acme.1password.com#top",
            "https://acme.1password.com/#",
            "not a url",
            "http://user:SECRET@acme.1password.com?next=/",
            "ftp://user:SECRET@acme.1password.com",
        ] {
            let error = require_sso(
                &login_info(Some("USERUUID"), Some(address)),
                "user@example.com",
            )
            .err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if !what.contains(address) && !what.contains("SECRET")),
                "unexpected result for '{address}': {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn start_sends_only_the_user_uuid() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path("/api/v3/auth/sso/oidc/start"))
                    .and(matchers::body_json(json!({"userUuid": "USERUUID"})))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"authRedirect": LOGIN_URL})),
                    )
                    .expect(1),
            )
            .await;

        let url = start_sso_login(&sso_account(), &rest_client(&server))
            .await
            .expect("starts");

        assert_eq!(url, LOGIN_URL);
        server.verify().await;
    }

    #[tokio::test]
    async fn start_returns_a_server_error() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v3/auth/sso/oidc/start")).respond_with(
                    ResponseTemplate::new(400)
                        .set_body_json(json!({"errorCode": 117, "errorMessage": "gone"})),
                ),
            )
            .await;

        let error = start_sso_login(&sso_account(), &rest_client(&server))
            .await
            .err();

        assert!(matches!(error, Some(OnePasswordError::NotFound)));
    }

    #[tokio::test]
    async fn perform_returns_the_code_and_state_of_the_c_example() {
        let redirect = vectors().redirect;
        let ui = ScriptedUi::redirected_to(&redirect.url);

        let (code, state) = perform_sso_login(LOGIN_URL, &ui).await.expect("performs");

        assert_eq!(code, redirect.code);
        assert_eq!(state, redirect.state);
        assert_eq!(
            ui.calls(),
            [(LOGIN_URL.to_string(), REDIRECT_TO.to_string())]
        );
    }

    #[tokio::test]
    async fn perform_reads_the_parameters_from_the_query_too() {
        let ui = ScriptedUi::redirected_to("https://acme.1password.com/cb?code=c0de&state=st4te");

        let (code, state) = perform_sso_login(LOGIN_URL, &ui).await.expect("performs");

        assert_eq!((code.as_str(), state.as_str()), ("c0de", "st4te"));
    }

    #[tokio::test]
    async fn perform_does_not_mistake_session_state_for_state() {
        let ui = ScriptedUi::redirected_to(
            "https://acme.1password.com/cb#session_state=WRONG&code=c0de&state=st4te",
        );

        let (_, state) = perform_sso_login(LOGIN_URL, &ui).await.expect("performs");

        assert_eq!(state, "st4te");
    }

    #[tokio::test]
    async fn perform_requires_a_state_of_its_own() {
        let ui = ScriptedUi::redirected_to(
            "https://acme.1password.com/cb#code=c0de&session_state=WRONG",
        );

        let error = perform_sso_login(LOGIN_URL, &ui).await.err();

        assert!(
            matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains("no state")),
            "unexpected result: {error:?}"
        );
    }

    #[tokio::test]
    async fn perform_form_decodes_the_redirect() {
        let ui = ScriptedUi::redirected_to("https://acme.1password.com/cb#code=a%2Bb&state=c+d");

        let (code, state) = perform_sso_login(LOGIN_URL, &ui).await.expect("performs");

        assert_eq!(code, "a+b");
        assert_eq!(state, "c d");
    }

    #[tokio::test]
    async fn perform_requires_a_code_and_a_state() {
        for (url, missing) in [
            ("https://acme.1password.com/cb#state=st4te", "code"),
            ("https://acme.1password.com/cb#code=&state=st4te", "code"),
            ("https://acme.1password.com/cb#code=c0de", "state"),
            ("https://acme.1password.com/cb#code=c0de&state=", "state"),
            ("https://acme.1password.com/cb", "code"),
        ] {
            let error = perform_sso_login(LOGIN_URL, &ScriptedUi::redirected_to(url))
                .await
                .err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains(&format!("no {missing}"))),
                "unexpected result for '{url}': {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn perform_requires_a_redirect_uri_before_asking_the_user() {
        for login_url in [
            "https://idp.example.com/authorize?client_id=abc",
            "https://idp.example.com/authorize?post_redirect_uri=https%3A%2F%2Fexample.com",
            "https://idp.example.com/authorize?redirect_uri=",
        ] {
            let ui = ScriptedUi::redirected_to("https://acme.1password.com/cb#code=c&state=s");

            let error = perform_sso_login(login_url, &ui).await.err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains("redirect_uri")),
                "unexpected result for '{login_url}': {error:?}"
            );
            assert!(ui.calls().is_empty());
        }
    }

    #[tokio::test]
    async fn perform_rejects_a_redirect_uri_that_is_not_a_web_address() {
        for redirect_uri in [
            "javascript%3Aalert(1)",
            "file%3A%2F%2F%2Fcb",
            "ftp%3A%2F%2Facme.1password.com%2Fcb",
            "%2F%2Facme.1password.com%2Fcb",
            "acme.1password.com%2Fcb",
        ] {
            let login_url = format!(
                "https://idp.example.com/authorize?redirect_uri={redirect_uri}&state=SECRET"
            );
            let ui = ScriptedUi::redirected_to("https://acme.1password.com/cb#code=c&state=s");

            let error = perform_sso_login(&login_url, &ui).await.err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains("redirect URI") && !what.contains("SECRET")),
                "unexpected result for '{login_url}': {error:?}"
            );
            assert!(ui.calls().is_empty(), "'{login_url}' reached the user");
        }
    }

    #[tokio::test]
    async fn perform_rejects_a_login_url_that_is_not_a_web_address() {
        for login_url in [
            "javascript:alert(1)//?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "file://idp.example.com/authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "ftp://idp.example.com/authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "file:///authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "https://?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "//idp.example.com/authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "idp.example.com/authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
        ] {
            let ui = ScriptedUi::redirected_to("https://acme.1password.com/cb#code=c&state=s");

            let error = perform_sso_login(login_url, &ui).await.err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if !what.contains("SECRET")),
                "unexpected result for '{login_url}': {error:?}"
            );
            assert!(ui.calls().is_empty(), "'{login_url}' reached the user");
        }
    }

    #[tokio::test]
    async fn perform_reports_a_cancel_as_canceled() {
        let ui = ScriptedUi::new(SsoLoginResult::Cancel);

        let error = perform_sso_login(LOGIN_URL, &ui).await.err();

        assert!(
            matches!(error, Some(OnePasswordError::Canceled)),
            "unexpected result: {error:?}"
        );
        assert_eq!(ui.calls().len(), 1);
    }

    #[test]
    fn url_parameters_match_whole_keys_in_the_query_and_the_fragment() {
        let url = "https://h/p?x_code=1&code=2&y=code=3#z=4&code=5";

        assert_eq!(url_parameter(url, "code").as_deref(), Some("2"));
        assert_eq!(url_parameter(url, "x_code").as_deref(), Some("1"));
        assert_eq!(url_parameter(url, "z").as_deref(), Some("4"));
        assert_eq!(url_parameter(url, "y").as_deref(), Some("code=3"));
        assert_eq!(url_parameter(url, "cod"), None);
        assert_eq!(
            url_parameter("https://h/p#code=5", "code").as_deref(),
            Some("5")
        );
        assert_eq!(
            url_parameter("https://h/p?a&code=1", "code").as_deref(),
            Some("1")
        );
    }

    #[test]
    fn url_parameters_are_form_decoded() {
        assert_eq!(
            url_parameter("u?a=%E2%9C%93+%2B%3D%26", "a").as_deref(),
            Some("\u{2713} +=&")
        );
    }

    #[tokio::test]
    async fn verify_sends_the_code_state_and_device_descriptor() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path("/api/v3/auth/sso/oidc/verify"))
                    .and(matchers::body_json(json!({
                        "code": "c0de",
                        "state": "st4te",
                        "device": client_info().sso_verify_device_body(),
                    })))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "type": "device_not_enrolled",
                        "user": {
                            "sessionUuid": "SESSIONUUID",
                            "accountUuid": "ACCOUNTUUID",
                            "userUuid": "USERUUID",
                            "email": "user@example.com",
                        },
                        "ssoAuth": {
                            "signInTokenDetails": {
                                "token": "SIGN_IN_TOKEN",
                                "publicKey": "PUBLICKEY",
                                "exp": "2030-01-01T00:00:00Z",
                            },
                        },
                    })))
                    .expect(1),
            )
            .await;

        let session = verify_sso_login("c0de", "st4te", &client_info(), &rest_client(&server))
            .await
            .expect("verifies");

        assert_eq!(session.state, "device_not_enrolled");
        assert_eq!(session.user.session_uuid, "SESSIONUUID");
        assert_eq!(
            session.sso_auth.sign_in_token_details.token.as_str(),
            "SIGN_IN_TOKEN"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn verify_returns_a_server_error() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v3/auth/sso/oidc/verify")).respond_with(
                    ResponseTemplate::new(400)
                        .set_body_json(json!({"errorCode": 500, "errorMessage": "bad code"})),
                ),
            )
            .await;

        let error = verify_sso_login("c0de", "st4te", &client_info(), &rest_client(&server))
            .await
            .err();

        assert!(
            matches!(error, Some(OnePasswordError::Internal(what)) if what.contains("bad code"))
        );
    }

    #[test]
    fn the_sign_in_token_stays_out_of_debug_output() {
        let output = format!("{:?}", session("device_not_enrolled"));

        assert!(!output.contains("SIGN_IN_TOKEN"), "leaked: {output}");
    }

    #[test]
    fn a_new_device_is_not_enrolled() {
        assert!(require_new_device(&session("device_not_enrolled")).is_ok());
    }

    #[test]
    fn any_other_session_state_is_an_error() {
        for state in ["", "found", "Found", "device_deleted", "unknown"] {
            let error = require_new_device(&session(state)).err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains(state)),
                "unexpected result for '{state}': {error:?}"
            );
        }
    }
}
