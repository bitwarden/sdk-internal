use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptchaResponse {
    /// hcaptcha site key
    pub site_key: String,
}

impl From<crate::auth::api::response::IdentityCaptchaResponse> for CaptchaResponse {
    fn from(api: crate::auth::api::response::IdentityCaptchaResponse) -> Self {
        Self {
            site_key: api.site_key,
        }
    }
}

impl From<String> for CaptchaResponse {
    fn from(s: String) -> Self {
        Self { site_key: s }
    }
}
