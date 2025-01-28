use bitwarden_crypto::{EncryptionContext, EncryptionContextBuilder};
use serde::{Deserialize, Serialize};

use super::{
    send_file_context::{SendFileContext, SendFileContextBuilder},
    send_name_context::{SendNameContext, SendNameContextBuilder},
    send_notes_context::{SendNotesContext, SendNotesContextBuilder},
    send_text_context::{SendTextContext, SendTextContextBuilder},
};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub(crate) enum SendContext {
    V1,
}

impl SendContext {
    pub(crate) fn name_context(&self) -> SendNameContext {
        match self {
            SendContext::V1 => SendNameContext::V1,
        }
    }

    pub(crate) fn text_context(&self) -> SendTextContext {
        match self {
            SendContext::V1 => SendTextContext::V1,
        }
    }

    pub(crate) fn file_context(&self) -> SendFileContext {
        match self {
            SendContext::V1 => SendFileContext::V1,
        }
    }

    pub(crate) fn notes_context(&self) -> SendNotesContext {
        match self {
            SendContext::V1 => SendNotesContext::V1,
        }
    }
}

impl EncryptionContext for SendContext {
    fn context_name() -> &'static str {
        "send"
    }
}

pub(crate) struct SendContextBuilder;

impl SendContextBuilder {
    pub(crate) fn name_context_builder(&self) -> SendNameContextBuilder {
        SendNameContextBuilder
    }

    pub(crate) fn text_context_builder(&self) -> SendTextContextBuilder {
        SendTextContextBuilder
    }

    pub(crate) fn file_context_builder(&self) -> SendFileContextBuilder {
        SendFileContextBuilder
    }

    pub(crate) fn notes_context_builder(&self) -> SendNotesContextBuilder {
        SendNotesContextBuilder
    }
}

impl EncryptionContextBuilder for SendContextBuilder {
    type Context = SendContext;

    fn build_like(&self, template_context: &Self::Context) -> Self::Context {
        match template_context {
            SendContext::V1 => SendContext::V1,
        }
    }
}
