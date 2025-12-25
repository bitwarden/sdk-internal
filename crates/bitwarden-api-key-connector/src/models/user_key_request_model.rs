use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserKeyKeyRequestModel {
    #[serde(rename = "key", alias = "Key")]
    pub key: String,
}
