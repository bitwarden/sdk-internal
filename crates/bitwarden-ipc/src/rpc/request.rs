use serde::{de::DeserializeOwned, Serialize};

pub trait RpcRequest: Serialize + DeserializeOwned {
    type Response: Serialize + DeserializeOwned;

    /// Used to identify handlers
    fn name() -> String;
}
