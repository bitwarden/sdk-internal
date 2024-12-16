use std::borrow::Cow;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CxpError {
    #[error("JSON error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(Cow<'static, str>),
}
