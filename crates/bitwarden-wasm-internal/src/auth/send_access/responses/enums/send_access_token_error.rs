use serde::Deserialize;

#[derive(Deserialize, PartialEq, Eq, Debug)]
pub enum SendAccessTokenError {
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "invalid_grant")]
    InvalidGrant,
}
