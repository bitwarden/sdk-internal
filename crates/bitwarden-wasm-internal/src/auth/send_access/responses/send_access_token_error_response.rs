use serde::Deserialize;

use crate::auth::send_access::responses::enums::{
    SendAccessTokenError, SendAccessTokenErrorDescription,
};

#[derive(Deserialize, Debug)]
pub struct SendAccessTokenErrorResponse {
    pub error: SendAccessTokenError,
    pub error_description: Option<SendAccessTokenErrorDescription>,
}
