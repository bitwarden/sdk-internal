use bitwarden_crypto::{EncryptionContext, EncryptionContextBuilder};
use serde::{Deserialize, Serialize};

use super::{
    send_file_context::{SendFileContext, SendFileContextBuilder}, send_key_context::{SendKeyContext, SendKeyContextBuilder}, send_name_context::{SendNameContext, SendNameContextBuilder}, send_notes_context::{SendNotesContext, SendNotesContextBuilder}, send_text_context::{SendTextContext, SendTextContextBuilder}
};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub(crate) enum SendContext {
    V1,
}

impl SendContext {
    pub(crate) fn name_context(&self) -> SendNameContext {
        SendNameContext::V1
    }

    pub(crate) fn text_context(&self) -> SendTextContext {
        SendTextContext::V1
    }

    pub(crate) fn file_context(&self) -> SendFileContext {
        SendFileContext::V1
    }

    pub(crate) fn notes_context(&self) -> SendNotesContext {
        SendNotesContext::V1
    }

    pub(crate) fn key_context(&self) -> SendKeyContext {
        SendKeyContext::V1
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

    pub(crate) fn key_context_builder(&self) -> SendKeyContextBuilder {
        SendKeyContextBuilder
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
