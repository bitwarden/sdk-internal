/// Go to parent and import the necessary modules.
use super::super::enums::SendAccessCredentials;

pub struct SendAccessTokenRequest {
    pub send_id: String,
    pub send_access_credentials: Option<SendAccessCredentials>,
}
