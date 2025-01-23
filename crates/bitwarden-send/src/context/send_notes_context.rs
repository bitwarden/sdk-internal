use bitwarden_crypto::{EncryptionContext, EncryptionContextBuilder};
use serde::{Deserialize, Serialize};


#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub(crate) enum SendNotesContext {
    V1
}

impl EncryptionContext for SendNotesContext {
    fn context_name(&self) -> &str {
        "send_Notes"
    }
}

pub(crate) struct SendNotesContextBuilder;

impl EncryptionContextBuilder for SendNotesContextBuilder {
    type Context = SendNotesContext;

    fn build_like(&self, template_context: &Self::Context) -> Self::Context {
        match template_context {
            SendNotesContext::V1 => SendNotesContext::V1,
        }
    }
}
