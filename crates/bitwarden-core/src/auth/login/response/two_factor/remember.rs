use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Remember {}

impl From<crate::auth::api::response::two_factor_provider_data::remember::Remember> for Remember {
    fn from(_: crate::auth::api::response::two_factor_provider_data::remember::Remember) -> Self {
        Self {}
    }
}
