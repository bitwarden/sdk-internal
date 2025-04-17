use crate::{message::PayloadTypeName, rpc::RpcPayload};

pub struct PingRequest;

pub struct PingResponse;

impl PayloadTypeName for PingRequest {
    fn name() -> String {
        "PingRequest".to_string()
    }
}

impl RpcPayload for PingRequest {
    // type RequestType = PingRequest;
    type ResponseType = PingResponse;
    type ErrorType = ();
}
