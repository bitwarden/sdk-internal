use bitwarden_crypto::{EncryptionContext, EncryptionContextBuilder};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub(crate) enum SendTextMessageContext {
    V1,
}

impl EncryptionContext for SendTextMessageContext {
    fn context_name() -> &'static str {
        "send_text_text"
    }
}

pub(crate) struct SendTextMessageContextBuilder;

impl EncryptionContextBuilder for SendTextMessageContextBuilder {
    type Context = SendTextMessageContext;

    fn build_like(&self, template_context: &Self::Context) -> Self::Context {
        match template_context {
            SendTextMessageContext::V1 => SendTextMessageContext::V1,
        }
    }
}
