use serde::Deserialize;

use crate::auth::send_access::responses::enums::{
    SendAccessTokenError, SendAccessTokenErrorDescription,
};

#[derive(Deserialize, Debug)]
/// The server response for an unsuccessful send access token request.
pub struct SendAccessTokenErrorResponse {
    /// The error string returned by the server.
    pub error: SendAccessTokenError,
    /// A long description of the error, if available.
    pub error_description: Option<SendAccessTokenErrorDescription>,
}
