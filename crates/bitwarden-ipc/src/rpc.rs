use crate::message::PayloadTypeName;

pub trait RpcPayload: PayloadTypeName {
    // /// The type of the request.
    // type RequestType;

    /// The type of the response.
    type ResponseType;

    /// The type of the error.
    type ErrorType;

    // /// Sends a request and returns a response.
    // fn send_request(&self, request: Self::RequestType) -> Result<Self::ResponseType, Self::ErrorType>;
}
