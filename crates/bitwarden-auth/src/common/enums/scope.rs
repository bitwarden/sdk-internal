use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum Scope {
    #[serde(rename = "api.send.access")]
    ApiSendAccess,
    // TODO: Add other scopes as needed.
}
