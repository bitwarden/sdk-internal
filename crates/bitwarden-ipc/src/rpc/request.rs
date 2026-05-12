use serde::{Serialize, de::DeserializeOwned};

/// Trait representing an RPC request.
pub trait RpcRequest: Serialize + DeserializeOwned + 'static {
    /// The type of the response that will be returned for this request.
    type Response: Serialize + DeserializeOwned + 'static;

    /// Used to identify handlers. This should be unique across all request types.
    const NAME: &str;
}
