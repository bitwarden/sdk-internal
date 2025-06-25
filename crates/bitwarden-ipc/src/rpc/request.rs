use serde::{de::DeserializeOwned, Serialize};

pub trait RpcRequest: Serialize + DeserializeOwned + 'static {
    type Response: Serialize + DeserializeOwned + 'static;

    /// Used to identify handlers
    const NAME: &str;
}
