use serde::Serialize;

pub trait RpcPayload {
    /// The type of the response.
    type Response: Serialize + for<'de> serde::Deserialize<'de>;

    /// The type of the error.
    type Error: Serialize + for<'de> serde::Deserialize<'de>;

    // /// Sends a request and returns a response.
    // fn send_request(&self, request: Self::RequestType) -> Result<Self::ResponseType, Self::ErrorType>;
    fn name() -> String;
}
