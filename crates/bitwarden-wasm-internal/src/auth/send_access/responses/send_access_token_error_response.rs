use serde::Deserialize;

use crate::auth::send_access::enums::{SendAccessTokenError, SendAccessTokenErrorDescription};

// TODO: add enums underneath responses / requests / etc  and keep top level enums as needed
// consider moving enums to common if used outside of send access

#[derive(Deserialize, Debug)]
pub struct SendAccessTokenErrorResponse {
    pub error: SendAccessTokenError,
    pub error_description: Option<SendAccessTokenErrorDescription>,
}
