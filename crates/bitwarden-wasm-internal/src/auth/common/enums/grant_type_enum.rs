use serde::{Deserialize, Serialize};

/// Add a trait to this enum to allow for serialization and deserialization of the enum values.
#[derive(Serialize, Deserialize, Debug)]
/// Instructs deserialization to map the string "send_access" to the `SendAccess` variant.
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    SendAccess,
    // TODO: Add other grant types as needed.
}
