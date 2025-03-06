use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Copy, Deserialize, Debug, JsonSchema, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CipherPermissions {
    pub delete: bool,
    pub restore: bool,
}
