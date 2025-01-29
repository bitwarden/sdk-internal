use bitwarden_crypto::{EncryptionContext, EncryptionContextBuilder};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub(crate) enum SendKeyContext {
    V1,
}

impl EncryptionContext for SendKeyContext {
    fn context_name() -> &'static str {
        "send_key"
    }
}

pub(crate) struct SendKeyContextBuilder;

impl EncryptionContextBuilder for SendKeyContextBuilder {
    type Context = SendKeyContext;

    fn build_like(&self, template_context: &Self::Context) -> Self::Context {
        match template_context {
            SendKeyContext::V1 => SendKeyContext::V1,
        }
    }
}
