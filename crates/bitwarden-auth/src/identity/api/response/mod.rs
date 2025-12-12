//! Response models for Identity API endpoints that cannot be auto-generated
//! (e.g., connect/token endpoints) and are shared across multiple features within the identity
//! client
//!
//! For standard controller endpoints, use the `bitwarden-api-identity` crate.
mod login_success_api_response;
pub(crate) use login_success_api_response::LoginSuccessApiResponse;

mod user_decryption_options_api_response;
pub(crate) use user_decryption_options_api_response::UserDecryptionOptionsApiResponse;

mod trusted_device_user_decryption_option_api_response;
pub(crate) use trusted_device_user_decryption_option_api_response::TrustedDeviceUserDecryptionOptionApiResponse;

mod key_connector_user_decryption_option_api_response;
pub(crate) use key_connector_user_decryption_option_api_response::KeyConnectorUserDecryptionOptionApiResponse;

mod webauthn_prf_user_decryption_option_api_response;
pub(crate) use webauthn_prf_user_decryption_option_api_response::WebAuthnPrfUserDecryptionOptionApiResponse;

mod login_error_api_response;
pub(crate) use login_error_api_response::{
    InvalidGrantError, LoginErrorApiResponse, OAuth2ErrorApiResponse, PasswordInvalidGrantError,
};
