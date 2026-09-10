//! The device identity presented to 1Password and its registration.

use rand::Rng;
use serde_json::{Value, json};

use super::{
    error::OnePasswordError,
    identity::{HTTP_LIB, PLATFORM, VERSION},
    rest::RestClient,
    wire::SuccessStatus,
};

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const DEVICE_UUID_LENGTH: usize = 26;
const DEVICE_ENDPOINT: &str = "v1/device";

/// Generates a 26-character 1Password device id from the lowercase base32 alphabet.
///
/// A fresh id per import is expected: the login registers it with the account and nothing uses it
/// afterwards.
pub fn generate_device_uuid() -> String {
    let mut rng = bitwarden_random::rng();
    (0..DEVICE_UUID_LENGTH)
        .map(|_| BASE32_ALPHABET[(rng.next_u32() % 32) as usize] as char)
        .collect()
}

/// Client identity headers sent with every request.
pub(super) struct ClientInfo {
    client_name: String,
    client_version: String,
    pub user_agent: String,
    pub op_user_agent: String,
    pub device_uuid: String,
}

impl ClientInfo {
    /// Impersonates the 1Password desktop client for the current platform.
    pub(super) fn for_desktop(device_uuid: &str) -> ClientInfo {
        let platform = PLATFORM;

        ClientInfo {
            client_name: format!("1Password for {}", platform.os),
            client_version: VERSION.to_string(),
            user_agent: format!("1Password for {}/{VERSION}", platform.os),
            op_user_agent: format!(
                "1|{}|{VERSION}|{device_uuid}|||{HTTP_LIB}|{}",
                platform.op_code, platform.os_suffix
            ),
            device_uuid: device_uuid.to_string(),
        }
    }

    pub(super) fn client_id(&self) -> String {
        format!("{}/{}", self.client_name, self.client_version)
    }

    /// The device descriptor sent to `v1/device` and inside `v2/auth/complete`.
    ///
    /// The real 1Password clients also send `model` and `osVersion`. The server accepted their
    /// removal when this was tested, so they are left out, but add them back if it starts
    /// rejecting the request.
    pub(super) fn device_body(&self) -> Value {
        json!({
            "uuid": self.device_uuid,
            "clientName": self.client_name,
            "clientVersion": self.client_version,
            // Shown in the account's device list, so it names us rather than a 1Password client.
            "name": "Bitwarden",
            "osName": PLATFORM.os_name,
            "userAgent": self.user_agent,
        })
    }
}

/// Registers the device with the server.
pub(super) async fn register_device(
    client_info: &ClientInfo,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let response: SuccessStatus = rest
        .post_json(DEVICE_ENDPOINT, client_info.device_body())
        .await?;
    check_success(response, "register", client_info)
}

/// Reauthorizes a previously deleted device.
pub(super) async fn reauthorize_device(
    client_info: &ClientInfo,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let response: SuccessStatus = rest
        .put(&format!(
            "{DEVICE_ENDPOINT}/{}/reauthorize",
            client_info.device_uuid
        ))
        .await?;
    check_success(response, "reauthorize", client_info)
}

fn check_success(
    response: SuccessStatus,
    action: &str,
    client_info: &ClientInfo,
) -> Result<(), OnePasswordError> {
    if response.success != 1 {
        return Err(OnePasswordError::Internal(format!(
            "failed to {action} the device '{}'",
            client_info.device_uuid
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitwarden_api_base::new_http_client;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::*;

    fn client(server: &MockServer) -> RestClient {
        let info = ClientInfo::for_desktop("device-uuid");
        RestClient::new(
            new_http_client(),
            format!("http://{}/api", server.address()),
            &info.client_id(),
            &info.user_agent,
            &info.op_user_agent,
        )
        .expect("valid headers")
    }

    #[test]
    fn generated_uuid_has_expected_shape() {
        let uuid = generate_device_uuid();
        assert_eq!(uuid.len(), DEVICE_UUID_LENGTH);
        assert!(uuid.bytes().all(|b| BASE32_ALPHABET.contains(&b)));
        assert_ne!(uuid, generate_device_uuid());
    }

    #[test]
    fn client_info_builds_identity_headers() {
        let info = ClientInfo::for_desktop("device-uuid");
        assert_eq!(info.client_id(), format!("{}/81210036", info.client_name));
        assert!(info.op_user_agent.contains("device-uuid"));
        assert!(info.user_agent.starts_with("1Password for "));
    }

    #[test]
    fn device_body_carries_the_device_descriptor() {
        let info = ClientInfo::for_desktop("device-uuid");
        let body = info.device_body();
        assert_eq!(body["uuid"], "device-uuid");
        assert_eq!(body["clientVersion"], "81210036");
        assert_eq!(body["osName"], PLATFORM.os_name);
        assert_eq!(body["clientName"], format!("1Password for {}", PLATFORM.os));
    }

    #[tokio::test]
    async fn registers_and_reauthorizes_the_device() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/device"))
                    .and(matchers::method("POST"))
                    .and(matchers::body_partial_json(json!({"uuid": "device-uuid"})))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 1})))
                    .expect(1),
            )
            .await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/device/device-uuid/reauthorize"))
                    .and(matchers::method("PUT"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 1})))
                    .expect(1),
            )
            .await;

        let rest = client(&server);
        let info = ClientInfo::for_desktop("device-uuid");
        register_device(&info, &rest).await.expect("registers");
        reauthorize_device(&info, &rest)
            .await
            .expect("reauthorizes");

        server.verify().await;
    }

    #[tokio::test]
    async fn reports_a_failed_registration() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/device"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 0})))
                    .expect(1),
            )
            .await;

        let error = register_device(&ClientInfo::for_desktop("device-uuid"), &client(&server))
            .await
            .expect_err("registration is rejected");

        assert!(error.to_string().contains("failed to register the device"));
        server.verify().await;
    }
}
