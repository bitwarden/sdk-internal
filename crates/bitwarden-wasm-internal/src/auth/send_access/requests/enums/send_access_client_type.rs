use serde::{Deserialize, Serialize};

/// Enum representing the type of client requesting a send access token.
/// Eventually, this could / should be merged with the existing `ClientType` enum
#[derive(Serialize, Deserialize, Debug)]
pub enum SendAccessClientType {
    /// Represents a Send client.
    /// This is a standalone client that lives within the BW web app, but has no context of a BW user.
    #[serde(rename = "send")]
    Send,
}
