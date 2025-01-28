use bitwarden_crypto::{EncryptionContext, EncryptionContextBuilder};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub(crate) enum SendFileNameContext {
    V1,
}

impl EncryptionContext for SendFileNameContext {
    fn context_name() -> &'static str {
        "send_file_name"
    }
}

pub(crate) struct SendFileNameContextBuilder;

impl EncryptionContextBuilder for SendFileNameContextBuilder {
    type Context = SendFileNameContext;

    fn build_like(&self, template_context: &Self::Context) -> Self::Context {
        match template_context {
            SendFileNameContext::V1 => SendFileNameContext::V1,
        }
    }
}
