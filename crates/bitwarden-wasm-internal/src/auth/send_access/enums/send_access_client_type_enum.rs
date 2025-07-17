use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum SendAccessClientType {
    #[serde(rename = "send")]
    Send,
}
