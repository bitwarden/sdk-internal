# Bitwarden Auth

Contains the implementation of the auth functionality for the Bitwarden Password Manager.

## Send Access

- Manages obtaining send access tokens for accessing secured send endpoints.

## Identity / Login

**LoginClient**: Authenticates Bitwarden users to obtain access tokens.

### Available Login Methods

- **Password**: Email and master password authentication (2FA not yet supported)
  - See
    [`login_via_password`](https://docs.rs/bitwarden-auth/latest/bitwarden_auth/identity/login_via_password/index.html)
    module for details and examples
- **Future**: SSO, device-based, etc.

### Quick Example

```rust,no_run
# use bitwarden_auth::{AuthClient, identity::login_via_password::PasswordLoginRequest};
# use bitwarden_auth::identity::models::{LoginRequest, LoginDeviceRequest, LoginResponse};
# use bitwarden_core::{Client, ClientSettings, DeviceType};
# async fn example(email: String, password: String) -> Result<(), Box<dyn std::error::Error>> {
# let client = Client::new(None);
# let auth_client = AuthClient::new(client);
# let settings = ClientSettings {
#     identity_url: "https://identity.bitwarden.com".to_string(),
#     api_url: "https://api.bitwarden.com".to_string(),
#     user_agent: "MyApp/1.0".to_string(),
#     device_type: DeviceType::SDK,
#     device_identifier: None,
#     bitwarden_client_version: None,
#     bitwarden_package_type: None,
# };
# let login_client = auth_client.login(settings);
// 1. Get user's KDF config
let prelogin = login_client.get_password_prelogin(email.clone()).await?;

// 2. Login with credentials
let response = login_client.login_via_password(PasswordLoginRequest {
    login_request: LoginRequest {
        client_id: "connector".to_string(),
        device: LoginDeviceRequest {
            device_type: DeviceType::SDK,
            device_identifier: "device-id".to_string(),
            device_name: "My Device".to_string(),
            device_push_token: None,
        },
    },
    email,
    password,
    prelogin_response: prelogin,
}).await?;

// 3. Use tokens from response for authenticated requests
match response {
    LoginResponse::Authenticated(success) => {
        let access_token = success.access_token;
        // Use access_token for authenticated requests
    }
}
# Ok(())
# }
```

See module documentation for complete examples and security details.
