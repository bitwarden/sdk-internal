use bitwarden_crypto::{EncryptionContext, EncryptionContextBuilder};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub(crate) enum SendNameContext {
    V1,
}

impl EncryptionContext for SendNameContext {
    fn context_name(&self) -> &str {
        "send_name"
    }
}

pub(crate) struct SendNameContextBuilder;

impl EncryptionContextBuilder for SendNameContextBuilder {
    type Context = SendNameContext;

    fn build_like(&self, template_context: &Self::Context) -> Self::Context {
        match template_context {
            SendNameContext::V1 => SendNameContext::V1,
        }
    }
}
