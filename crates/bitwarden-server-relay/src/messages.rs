use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ProtocolPayload {
    AuthRequest {
        userkey: Vec<u8>,
        email: String,
        auth_request_id: String,
    },
    DeviceId(String),
}
