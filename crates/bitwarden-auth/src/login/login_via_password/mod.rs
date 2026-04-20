//! Password-based authentication for Bitwarden users.
//!
//! This module implements the password login flow, which requires two steps:
//!
//! 1. **Prelogin**: Retrieve the user's KDF configuration with
//!    [`LoginClient::get_password_prelogin`]
//! 2. **Login**: Authenticate with [`LoginClient::login_via_password`] using the KDF settings
//!
//! # Security Model
//!
//! The master password is **never sent to the server**. Instead:
//! - User's KDF settings (PBKDF2 or Argon2id) are fetched during prelogin
//! - Master password is stretched with KDF to derive the master key
//! - Master key is stretched again into an AES256-CBC-HMAC key to unwrap the user key
//! - Master key is hashed with single-round PBKDF2 (using password as salt) to create the server
//!   authentication hash
//! - Only the authentication hash is transmitted to the server
//! - All requests include no-cache headers to prevent sensitive data caching
//!
//! # Current Limitations
//!
//! - Two-factor authentication (2FA) not yet supported
//! - New device verification not yet implemented
//!
//! # Complete Example
//!
//! ```rust,no_run
//! # use bitwarden_auth::{AuthClient, AuthClientExt};
//! # use bitwarden_auth::login::login_via_password::PasswordLoginRequest;
//! # use bitwarden_auth::login::models::{LoginRequest, LoginDeviceRequest, LoginResponse};
//! # use bitwarden_core::{Client, ClientSettings, DeviceType};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create the core client
//! let client = Client::new(None);
//! let auth_client = AuthClient::new(client);
//!
//! // Create login client with settings
//! let settings = ClientSettings {
//!     identity_url: "https://identity.bitwarden.com".to_string(),
//!     api_url: "https://api.bitwarden.com".to_string(),
//!     user_agent: "MyApp/1.0".to_string(),
//!     device_type: DeviceType::SDK,
//!     device_identifier: None,
//!     bitwarden_client_version: None,
//!     bitwarden_package_type: None,
//! };
//! let login_client = auth_client.login(settings);
//!
//! // Step 1: Get user's KDF configuration
//! let prelogin = login_client
//!     .get_password_prelogin("user@example.com".to_string())
//!     .await?;
//!
//! // Step 2: Construct and send login request
//! let response = login_client.login_via_password(PasswordLoginRequest {
//!     login_request: LoginRequest {
//!         client_id: "connector".to_string(),
//!         device: LoginDeviceRequest {
//!             device_type: DeviceType::SDK,
//!             device_identifier: "device-id".to_string(),
//!             device_name: "My Device".to_string(),
//!             device_push_token: None,
//!         },
//!     },
//!     email: "user@example.com".to_string(),
//!     password: "master-password".to_string(),
//!     prelogin_response: prelogin,
//! }).await?;
//!
//! // Step 3: Use tokens from response for authenticated requests
//! match response {
//!     LoginResponse::Authenticated(success) => {
//!         let access_token = success.access_token;
//!         // Use access_token for authenticated requests
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`LoginClient::get_password_prelogin`]: crate::login::LoginClient::get_password_prelogin
//! [`LoginClient::login_via_password`]: crate::login::LoginClient::login_via_password

mod login_via_password_impl;
mod password_login_api_request;
mod password_login_request;
mod password_prelogin;

pub(crate) use password_login_api_request::PasswordLoginApiRequest;
pub use password_login_request::PasswordLoginRequest;
pub use password_prelogin::PasswordPreloginError;

mod password_prelogin_response;
pub use password_prelogin_response::PasswordPreloginResponse;

mod password_login_error;
pub use password_login_error::PasswordLoginError;
