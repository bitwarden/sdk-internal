use bitwarden_crypto::{EncryptionContext, EncryptionContextBuilder};
use serde::{Deserialize, Serialize};

use super::send_name_context::{SendNameContext, SendNameContextBuilder};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub(crate) enum SendFileContext {
    V1
}

impl SendFileContext {
    pub(crate) fn file_name_context(&self) -> SendNameContext {
        match self {
            SendFileContext::V1 => SendNameContext::V1,
        }
    }
}

impl EncryptionContext for SendFileContext {
    fn context_name(&self) -> &str {
        "send_file"
    }
}

pub(crate) struct SendFileContextBuilder;

impl SendFileContextBuilder {
    pub(crate) fn file_name_context_builder(&self) -> SendNameContextBuilder {
        SendNameContextBuilder
    }
}

impl EncryptionContextBuilder for SendFileContextBuilder {
    type Context = SendFileContext;

    fn build_like(&self, template_context: &Self::Context) -> Self::Context {
        match template_context {
            SendFileContext::V1 => SendFileContext::V1,
        }
    }
}
