use bitwarden_crypto::{EncryptionContext, EncryptionContextBuilder};
use serde::{Deserialize, Serialize};

use super::send_text_message_context::{SendTextMessageContext, SendTextMessageContextBuilder};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub(crate) enum SendTextContext {
    V1
}

impl SendTextContext {
    pub(crate) fn text_message_context(&self) -> SendTextMessageContext {
        match self {
            SendTextContext::V1 => SendTextMessageContext::V1,
        }
    }
}

impl EncryptionContext for SendTextContext {
    fn context_name(&self) -> &str {
        "send_text"
    }
}

pub(crate) struct SendTextContextBuilder;

impl SendTextContextBuilder {
    pub(crate) fn text_message_context_builder(&self) -> SendTextMessageContextBuilder {
        SendTextMessageContextBuilder
    }
}

impl EncryptionContextBuilder for SendTextContextBuilder {
    type Context = SendTextContext;

    fn build_like(&self, template_context: &Self::Context) -> Self::Context {
        match template_context {
            SendTextContext::V1 => SendTextContext::V1,
        }
    }
}
