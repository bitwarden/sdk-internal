use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum Scope {
    #[serde(rename = "api.send")]
    Send,
    // TODO: Add other scopes as needed.
}
