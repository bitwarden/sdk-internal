use bitwarden_api_api::models::FolderResponseModel;
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{
    CryptoError, Decryptable, EncString, Encryptable, IdentifyKey, KeyStoreContext,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[cfg(feature = "wasm")]
use {tsify_next::Tsify, wasm_bindgen::prelude::*};

use crate::VaultParseError;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Folder {
    id: Option<Uuid>,
    name: EncString,
    revision_date: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct FolderView {
    pub id: Option<Uuid>,
    pub name: String,
    pub revision_date: DateTime<Utc>,
}

impl IdentifyKey<SymmetricKeyId> for Folder {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::User
    }
}
impl IdentifyKey<SymmetricKeyId> for FolderView {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::User
    }
}

impl Encryptable<KeyIds, SymmetricKeyId, Folder> for FolderView {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Folder, CryptoError> {
        Ok(Folder {
            id: self.id,
            name: self.name.encrypt(ctx, key)?,
            revision_date: self.revision_date,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, FolderView> for Folder {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<FolderView, CryptoError> {
        Ok(FolderView {
            id: self.id,
            name: self.name.decrypt(ctx, key).ok().unwrap_or_default(),
            revision_date: self.revision_date,
        })
    }
}

impl TryFrom<FolderResponseModel> for Folder {
    type Error = VaultParseError;

    fn try_from(folder: FolderResponseModel) -> Result<Self, Self::Error> {
        Ok(Folder {
            id: folder.id,
            name: require!(EncString::try_from_optional(folder.name)?),
            revision_date: require!(folder.revision_date).parse()?,
        })
    }
}
