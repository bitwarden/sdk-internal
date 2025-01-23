use bitwarden_common::encoding::{B64DecodeError, B64Encoded, Encodable};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionContextError {
    #[error("Decryption context name mismatch: {expected} != {got}")]
    ContextNameMismatch { expected: String, got: String },
    #[error("Decryption context mismatch")]
    ContextMismatch,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[deprecated(
    note = "Use of NoContext provides no security, implement a specific context and context builder"
)]
pub struct NoContext;

impl NoContext {
    pub fn builder(_: &Self) -> Self {
        NoContext {}
    }

    pub fn duplicate(&self) -> Self {
        NoContext {}
    }
}

#[deprecated(
    note = "Use of NoContext provides no security, implement a specific context builder and context"
)]
pub struct NoContextBuilder;

impl EncryptionContextBuilder for NoContextBuilder {
    type Context = NoContext;
    fn build_like(&self, _: &Self::Context) -> Self::Context {
        NoContext {}
    }
}

impl EncryptionContextBuilder for NoContext {
    type Context = NoContext;
    fn build_like(&self, _: &Self::Context) -> Self::Context {
        NoContext {}
    }
}

impl EncryptionContext for NoContext {
    fn context_name(&self) -> &str {
        "NoContext"
    }
}

pub trait EncryptionContextBuilder {
    type Context: EncryptionContext;
    fn build_like(&self, template_context: &Self::Context) -> Self::Context;
}

pub trait EncryptionContext: Serialize + for<'a> Deserialize<'a> + PartialEq {
    /// A short name to describe the purpose of the context. This context name is validated for all
    /// values automatically and should never be changed
    fn context_name(&self) -> &str;

    fn validate_context_name(&self, other: String) -> Result<(), EncryptionContextError> {
        if self.context_name() == other {
            Ok(())
        } else {
            Err(EncryptionContextError::ContextNameMismatch {
                expected: self.context_name().to_string(),
                got: other,
            })
        }
    }

    fn validate(
        from_encrypted: Self,
        builder: impl FnOnce(&Self) -> Self,
    ) -> Result<(), EncryptionContextError> {
        let expected = builder(&from_encrypted);
        if expected == from_encrypted {
            Ok(())
        } else {
            Err(EncryptionContextError::ContextMismatch)
        }
    }

    fn get(&self) -> Vec<u8> {
        rmp_serde::to_vec(&(self.context_name(), self)).expect("rmp_serde should always serialize")
    }

    fn get_encoded(&self) -> B64Encoded {
        let rmp = self.get();
        rmp.encode()
    }

    fn try_from_encoded(b64: B64Encoded) -> Result<(String, Self), EncryptionContextEncodingError> {
        let rmp = Vec::<u8>::try_decode(b64)?;
        Ok(rmp_serde::from_slice(&rmp)?)
    }

    fn full_validate(
        &self,
        other: Self,
        other_name: String,
        builder: impl FnOnce(&Self) -> Self,
    ) -> Result<(), EncryptionContextError> {
        self.validate_context_name(other_name)?;
        Self::validate(other, builder)
    }
}

#[derive(Debug, Error)]
pub enum EncryptionContextEncodingError {
    #[error("Error decoding base 64: {0}")]
    InvalidBase64(#[from] B64DecodeError),
    #[error("Error decoding rmp: {0}")]
    InvalidRmp(#[from] rmp_serde::decode::Error),
}
