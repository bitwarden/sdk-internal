use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{
    EncString, KeyStoreContext,
    safe::{DataEnvelope, SealableVersionedData},
};
use serde::{Deserialize, Serialize};

use crate::AgentFillApprovalError;

const FORMAT_VERSION: u8 = 1;

/// Sealed container for an approval request or response: a `DataEnvelope` and its content key,
/// wrapped by the user key.
///
/// Uses the same JSON shape and version check as `SealedCipherBlob`. The server stores the JSON
/// string without opening it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(super) struct SealedApproval {
    format_version: u8,
    wrapped_cek: EncString,
    envelope: DataEnvelope,
}

impl SealedApproval {
    /// Seals `data` under a new content key wrapped by `wrapping_key`. The envelope's namespace
    /// comes from `T`.
    pub(super) fn seal<T: SealableVersionedData>(
        data: T,
        wrapping_key: &SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<Self, AgentFillApprovalError> {
        let (envelope, wrapped_cek) = DataEnvelope::seal_with_wrapping_key(data, wrapping_key, ctx)
            .map_err(|_| AgentFillApprovalError::Seal)?;
        Ok(Self {
            format_version: FORMAT_VERSION,
            wrapped_cek,
            envelope,
        })
    }

    /// Opens the container with `wrapping_key`. Fails if the envelope wasn't sealed under `T`'s
    /// namespace.
    pub(super) fn unseal<T: SealableVersionedData>(
        &self,
        wrapping_key: &SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<T, AgentFillApprovalError> {
        if self.format_version != FORMAT_VERSION {
            return Err(AgentFillApprovalError::Unseal);
        }
        self.envelope
            .unseal_with_wrapping_key(wrapping_key, &self.wrapped_cek, ctx)
            .map_err(|_| AgentFillApprovalError::Unseal)
    }

    /// Serializes this container into the opaque JSON string the server stores.
    pub(super) fn to_opaque_string(&self) -> Result<String, AgentFillApprovalError> {
        serde_json::to_string(self).map_err(|_| AgentFillApprovalError::Seal)
    }

    /// Parses a container from the opaque JSON string the server stores.
    pub(super) fn from_opaque_string(s: &str) -> Result<Self, AgentFillApprovalError> {
        serde_json::from_str(s).map_err(|_| AgentFillApprovalError::Unseal)
    }
}
