use serde::{Deserialize, Serialize};

/// Enum representing the type of client requesting a send access token.
/// Eventually, this could / should be merged with the existing `ClientType` enum
#[derive(Serialize, Deserialize, Debug)]
pub enum SendAccessClientType {
    #[serde(rename = "send")]
    Send,
}
